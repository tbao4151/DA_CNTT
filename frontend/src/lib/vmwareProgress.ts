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
// Preserve microsecond ordering instead of Date.parse's millisecond rounding.
// The caller has already validated strict UTC ISO-8601, including its calendar.
function utcChronologyKey(timestamp: string): string {
  const base = timestamp.replace(/(?:Z|\+00:00)$/, "");
  const [whole, fraction = ""] = base.split(".");
  return whole + "." + fraction.padEnd(6, "0");
}

// JSON.parse silently keeps the final occurrence of a repeated property.
// Scan the validated JSON source *before* trusting that normalized object.
// Keep a separate key set per object, including nested counts and result.
// Strings are consumed as whole tokens so embedded quotes/braces cannot
// masquerade as object syntax. Escaped key spellings are refused as well.
function rejectAmbiguousJsonKeys(source: string): void {
  type Scope = { kind: "object"; keys: Set<string> } | { kind: "array" };
  const scopes: Scope[] = [];
  for (let i = 0; i < source.length; i += 1) {
    const char = source[i];
    if (char === '"') {
      const start = ++i;
      while (i < source.length) {
        if (source[i] === "\\") {
          i += 2;
          continue;
        }
        if (source[i] === '"') break;
        i += 1;
      }
      let next = i + 1;
      while (next < source.length && /\s/.test(source[next])) next += 1;
      if (source[next] !== ":") continue;
      const scope = scopes[scopes.length - 1];
      if (!scope || scope.kind !== "object") {
        throw new Error("Khóa JSONL không thuộc đối tượng hợp lệ.");
      }
      const key = source.slice(start, i);
      if (key.includes("\\")) {
        throw new Error("Từ chối tên khóa JSONL dùng ký tự escape.");
      }
      if (scope.keys.has(key)) {
        throw new Error("Từ chối khóa JSONL trùng lặp, kể cả trong đối tượng lồng nhau.");
      }
      scope.keys.add(key);
    } else if (char === "{") {
      scopes.push({ kind: "object", keys: new Set<string>() });
    } else if (char === "[") {
      scopes.push({ kind: "array" });
    } else if (char === "}" || char === "]") {
      scopes.pop();
    }
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
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(item.observed_at_utc) ||
    Number.isNaN(Date.parse(item.observed_at_utc)) ||
    new Date(Date.parse(item.observed_at_utc)).toISOString().slice(0, 19) !== item.observed_at_utc.slice(0, 19) ||
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
      if (!COUNTS.has(key) || typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > 10000) {
        throw new Error("Bộ đếm thử nghiệm JSONL không hợp lệ.");
      }
      counts[key] = value;
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
    return status;
  }

  // Matches the exact redacted CLI terminal payload. Never consume original
  // network scope, private filenames or the internal raw run_sequence report.
  if (item.attack_executed !== undefined ||
      item.operational_ai_detection_verified !== undefined ||
      item.soc_alerts_created !== undefined) {
    throw new Error("Dòng kết thúc chứa trường ngoài hợp đồng.");
  }
  const result = object(item.result);
  keysMatch(result, [
    "mode", "network_attempts", "captured_log_flow_count",
    "research_candidate_count", "ssh_fetch_performed",
    "blue_research_scoring_performed", "vmware_isolation_verified",
    "attack_executed", "operational_ai_detection_verified",
    "soc_alerts_created",
  ]);
  const safeCount = (value: unknown): value is number =>
    typeof value === "number" && Number.isSafeInteger(value) &&
    value >= 0 && value <= 10000;
  if (
    !safeCount(result.network_attempts) ||
    !(result.captured_log_flow_count === null || safeCount(result.captured_log_flow_count)) ||
    !(result.research_candidate_count === null || safeCount(result.research_candidate_count)) ||
    result.vmware_isolation_verified !== false ||
    result.attack_executed !== false ||
    result.operational_ai_detection_verified !== false ||
    result.soc_alerts_created !== false ||
    typeof result.ssh_fetch_performed !== "boolean" ||
    typeof result.blue_research_scoring_performed !== "boolean"
  ) {
    throw new Error("Dòng tổng kết JSONL chứa dữ liệu hoặc tuyên bố không hợp lệ.");
  }
  if (status === "dry_run") {
    if (result.mode !== "DRY_RUN_EXECUTION_OFF" ||
        result.network_attempts !== 0 ||
        result.captured_log_flow_count !== null ||
        result.research_candidate_count !== null ||
        result.ssh_fetch_performed !== false ||
        result.blue_research_scoring_performed !== false) {
      throw new Error("Dry-run không được tuyên bố kết nối VMware, AI hoặc SOC.");
    }
  } else if (
    result.mode !== "STEPWISE_VMWARE_BENIGN_CAPTURE" ||
    result.ssh_fetch_performed !== true ||
    !safeCount(result.captured_log_flow_count) ||
    (result.blue_research_scoring_performed
      ? !safeCount(result.research_candidate_count)
      : result.research_candidate_count !== null)
  ) {
    throw new Error("Dòng hoàn tất không khớp bằng chứng thu thập/chấm điểm.");
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
  let redactedTerminalCounts: Record<string, unknown> | null = null;
  const events: VMwareStageEvent[] = [];
  // A valid completed CLI trace has exactly these nine stage records.
  // Before completion, only a prefix is accepted (e.g. interrupted SCP).
  const expected: ReadonlyArray<readonly [Stage, Status | "skipped_or_completed"]> = [
    ["preflight", "completed"],
    ["red", "running"], ["red", "completed"],
    ["zeek", "running"], ["zeek", "completed"],
    ["blue", "skipped_or_completed"],
    ["audit", "running"], ["audit", "completed"], ["soc", "skipped"],
  ];
  const expectedCounts: Partial<Record<string, readonly string[]>> = {
    "red:completed": ["attempted_probes"],
    "zeek:completed": ["snapshot_flow_count"],
    "blue:completed": ["research_candidate_count"],
    "audit:completed": ["candidate_matches", "unmatched_attempts"],
  };
  let dryRunSeen = false;
  for (const line of nonempty) {
    let decoded: unknown;
    try {
      decoded = JSON.parse(line) as unknown;
    } catch {
      throw new Error("Tệp JSONL có dòng không phải JSON hoàn chỉnh.");
    }
    rejectAmbiguousJsonKeys(line);
    const record = object(decoded);
    if (terminal !== null) throw new Error("Tệp có sự kiện sau dòng kết thúc.");
    if (record.kind === "da005_vmware_stepwise_terminal_v1") {
      terminal = terminalFrom(record);
      if (terminal === "completed") {
        redactedTerminalCounts = object(record.result);
      }
      continue;
    }
    const event = eventFrom(record, events.length + 1);
    if (events.length > 0) {
      const previousTime = utcChronologyKey(events[events.length - 1].observed_at_utc);
      if (utcChronologyKey(event.observed_at_utc) < previousTime) {
        throw new Error("Thời gian UTC của sự kiện đi ngược, từ chối phiên JSONL.");
      }
    }
    if (events.length === 0 && event.stage === "preflight" && event.status === "dry_run") {
      dryRunSeen = true;
    } else {
      if (dryRunSeen || events.length >= expected.length) {
        throw new Error("Dry-run hoặc phiên kết thúc không được tiếp tục thực thi.");
      }
      const [stage, status] = expected[events.length];
      if (event.stage !== stage ||
          (status === "skipped_or_completed"
            ? !["skipped", "completed"].includes(event.status)
            : event.status !== status)) {
        throw new Error("Thiếu, đảo hoặc giả mạo giai đoạn JSONL.");
      }
      const required = expectedCounts[event.stage + ":" + event.status] ?? [];
      const present = Object.keys(event.counts).sort();
      if (present.length !== required.length ||
          !present.every((key, index) => key === [...required].sort()[index])) {
        throw new Error("Bộ đếm không khớp giai đoạn chương trình.");
      }
    }
    events.push(event);
  }
  if (terminal === "dry_run" &&
      (events.length !== 1 || events[0].stage !== "preflight" || events[0].status !== "dry_run")) {
    throw new Error("Dữ liệu dry-run không khớp quy trình.");
  }
  if (terminal === "completed" &&
      (events.length !== expected.length || dryRunSeen ||
       events[events.length - 1].stage !== "soc" ||
       events[events.length - 1].status !== "skipped")) {
    throw new Error("Phiên kết thúc trước khi có bằng chứng các bước.");
  }
  // Event/terminal consistency: even fully schema-valid JSONL must not
  // display contradictory probe or Zeek counts as software evidence.
  // This checks only internal coherence, NOT physical packet authenticity.
  if (terminal === "completed") {
    const report = redactedTerminalCounts;
    if (!report ||
        report.network_attempts !== events[2].counts.attempted_probes ||
        report.captured_log_flow_count !== events[4].counts.snapshot_flow_count ||
        report.blue_research_scoring_performed !== (events[5].status === "completed") ||
        (events[5].status === "completed" &&
          report.research_candidate_count !== events[5].counts.research_candidate_count)) {
      throw new Error("Dòng tổng kết JSONL không khớp bộ đếm giai đoạn. Từ chối hiển thị.");
    }
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
