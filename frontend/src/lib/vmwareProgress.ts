/**
 * Strict, LOCAL-ONLY viewer contract for operator-assisted VMware JSONL.
 *
 * This does not connect to VMware, execute probes, score an AI model, or
 * authenticate capture provenance. Imported bytes never leave this browser.
 * Incomplete trailing lines are ignored until a later file refresh.
 */
export const MAX_VMWARE_PROGRESS_BYTES = 1024 * 1024;
const MAX_LINES = 128;
const STAGES = ["preflight", "red", "zeek", "blue", "audit", "soc"] as const;
const STATUSES = ["dry_run", "running", "completed", "skipped"] as const;
type Stage = (typeof STAGES)[number];
type Status = (typeof STATUSES)[number];
type TerminalStatus = "completed" | "dry_run" | "refused";

export type VMwareStageEvent = {
  kind: "da005_vmware_stepwise_progress_v1";
  seq: number;
  observed_at_utc: string;
  stage: Stage;
  status: Status;
  mode: "operator_assisted_benign_hostonly_experiment";
  counts: Record<string, number>;
};
export type VMwareProgressSnapshot = {
  events: VMwareStageEvent[];
  terminal: TerminalStatus | null;
  pendingLastLine: boolean;
  hasActivity: boolean;
};
const COUNTS = new Set([
  "attempted_probes",
  "snapshot_flow_count",
  "research_candidate_count",
  "candidate_matches",
  "unmatched_attempts",
]);
const FALSE_FLAGS = [
  "vmware_isolation_verified",
  "attack_executed",
  "ai_attack_planning_executed",
  "operational_ai_detection_verified",
  "soc_alerts_created",
] as const;

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Tệp không đúng định dạng sự kiện JSONL của DA005.");
  }
  return value as Record<string, unknown>;
}
function keysMatch(record: Record<string, unknown>, allowed: readonly string[]): void {
  if (Object.keys(record).some((key) => !allowed.includes(key))) {
    throw new Error("Tệp chứa thuộc tính không được phép trong hợp đồng JSONL.");
  }
}
function requireFalseFlags(record: Record<string, unknown>): void {
  if (FALSE_FLAGS.some((flag) => record[flag] !== false)) {
    throw new Error("Từ chối sự kiện tuyên bố hoạt động VMware/AI/SOC chưa xác minh.");
  }
}
function eventFrom(value: unknown, expectedSeq: number): VMwareStageEvent {
  const item = object(value);
  keysMatch(item, [
    "kind", "seq", "observed_at_utc", "stage", "status", "mode",
    "stage_evidence", ...FALSE_FLAGS, "counts",
  ]);
  requireFalseFlags(item);
  if (
    item.kind !== "da005_vmware_stepwise_progress_v1" ||
    item.seq !== expectedSeq ||
    item.mode !== "operator_assisted_benign_hostonly_experiment" ||
    item.stage_evidence !== "program_execution_only_not_independently_verified" ||
    typeof item.observed_at_utc !== "string" ||
    !/(Z|\+00:00)$/.test(item.observed_at_utc) ||
    Number.isNaN(Date.parse(item.observed_at_utc)) ||
    typeof item.stage !== "string" ||
    !STAGES.includes(item.stage as Stage) ||
    typeof item.status !== "string" ||
    !STATUSES.includes(item.status as Status)
  ) {
    throw new Error("Thứ tự hoặc provenance của JSONL không hợp lệ.");
  }
  const stage = item.stage as Stage;
  const status = item.status as Status;
  const permitted: Record<Stage, readonly Status[]> = {
    preflight: ["dry_run", "completed"],
    red: ["running", "completed"],
    zeek: ["running", "completed"],
    blue: ["completed", "skipped"],
    audit: ["running", "completed"],
    soc: ["skipped"],
  };
  if (!permitted[stage].includes(status)) {
    throw new Error("Trạng thái giai đoạn không phù hợp với luồng VMware an toàn.");
  }
  const counts: Record<string, number> = {};
  if (item.counts !== undefined) {
    const entries = Object.entries(object(item.counts));
    if (entries.length > 5) throw new Error("Số lượng bộ đếm không hợp lệ.");
    for (const [key, value] of entries) {
      if (!COUNTS.has(key) || !Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > 10000) {
        throw new Error("Bộ đếm thử nghiệm JSONL không hợp lệ.");
      }
      counts[key] = Number(value);
    }
  }
  return {
    kind: "da005_vmware_stepwise_progress_v1",
    seq: expectedSeq,
    observed_at_utc: item.observed_at_utc,
    stage, status,
    mode: "operator_assisted_benign_hostonly_experiment",
    counts,
  };
}

function terminalFrom(value: unknown): TerminalStatus {
  const item = object(value);
  keysMatch(item, [
    "kind", "status", "result", "attack_executed",
    "operational_ai_detection_verified", "soc_alerts_created",
  ]);
  if (item.kind !== "da005_vmware_stepwise_terminal_v1" ||
      !["completed", "dry_run", "refused"].includes(String(item.status))) {
    throw new Error("Dòng kết thúc JSONL không hợp lệ.");
  }
  const status = item.status as TerminalStatus;
  if (status === "refused") {
    if (item.result !== undefined || item.attack_executed !== false ||
        item.operational_ai_detection_verified !== false || item.soc_alerts_created !== false) {
      throw new Error("Dòng từ chối có nguồn gốc không hợp lệ.");
    }
  } else {
    const result = object(item.result);
    if (status === "dry_run") {
      if (result.mode !== "DRY_RUN_EXECUTION_OFF" ||
          result.ssh_fetch_performed !== false ||
          result.blue_research_scoring_performed !== false ||
          result.automated_soc_alerts !== false) {
        throw new Error("Dry-run không được tuyên bố kết nối VMware hoặc SOC.");
      }
    } else if (
      result.mode !== "STEPWISE_VMWARE_BENIGN_CAPTURE" ||
      result.attack_executed !== false ||
      result.operational_detection_verified !== false ||
      result.automated_soc_alerts !== false ||
      result.full_one_click_dual_ai !== false ||
      result.vmware_isolation_verified !== false
    ) {
      throw new Error("Dòng hoàn tất chứa tuyên bố live AI/VMware không hợp lệ.");
    }
  }
  return status;
}

export function parseVMwareProgressJsonl(text: string): VMwareProgressSnapshot {
  if (typeof text !== "string" || text.length > MAX_VMWARE_PROGRESS_BYTES) {
    throw new Error("Tệp JSONL quá lớn hoặc không hợp lệ.");
  }
  // Every completed print() from the Python CLI has its own trailing newline.
  // A partially-written final line must never be accepted as evidence.
  const endsInNewline = /(?:\n|\r)$/.test(text);
  const lines = text.split(/\r?\n/);
  if (!endsInNewline) lines.pop();
  const nonempty = lines.filter((line) => line.trim().length !== 0);
  if (nonempty.length > MAX_LINES) throw new Error("Quá nhiều dòng tiến độ trong một phiên.");
  let terminal: TerminalStatus | null = null;
  const events: VMwareStageEvent[] = [];
  let previousStage = -1;
  let previousStatus = "";
  for (const line of nonempty) {
    let decoded: unknown;
    try {
      decoded = JSON.parse(line) as unknown;
    } catch {
      throw new Error("Tệp JSONL có dòng không phải JSON hoàn chỉnh.");
    }
    const record = object(decoded);
    if (terminal !== null) throw new Error("Tệp có sự kiện sau dòng kết thúc.");
    if (record.kind === "da005_vmware_stepwise_terminal_v1") {
      terminal = terminalFrom(record);
      continue;
    }
    const event = eventFrom(record, events.length + 1);
    const stageIndex = STAGES.indexOf(event.stage);
    if (stageIndex < previousStage ||
        (stageIndex === previousStage && (previousStatus !== "running" || event.status !== "completed"))) {
      throw new Error("Các giai đoạn JSONL bị đảo hoặc trùng trạng thái.");
    }
    if (previousStage === 0 && previousStatus === "dry_run") {
      throw new Error("Dry-run không được có giai đoạn thực thi.");
    }
    previousStage = stageIndex;
    previousStatus = event.status;
    events.push(event);
  }
  if (terminal === "dry_run" &&
      (events.length !== 1 || events[0].stage !== "preflight" || events[0].status !== "dry_run")) {
    throw new Error("Dữ liệu dry-run không khớp quy trình.");
  }
  if (terminal === "completed" &&
      (events.length === 0 || events[events.length - 1].stage !== "soc" ||
       events[events.length - 1].status !== "skipped")) {
    throw new Error("Phiên kết thúc trước khi có bằng chứng các bước.");
  }
  return {
    events,
    terminal,
    pendingLastLine: !endsInNewline && text.length > 0,
    hasActivity: nonempty.length > 0,
  };
}

export const VMWARE_STAGE_LABELS: Record<Stage, string> = {
  preflight: "Preflight · Kiểm tra cấu hình",
  red: "Red · Lưu lượng lành tính",
  zeek: "Zeek · Thu thập snapshot",
  blue: "Blue · Chấm điểm nghiên cứu",
  audit: "Audit · Liên kết bằng chứng",
  soc: "SOC · Không tự động tạo cảnh báo",
};
