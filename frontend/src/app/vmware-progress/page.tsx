"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AppShell } from "@/components/AppShell";
import {
  MAX_VMWARE_PROGRESS_BYTES,
  parseVMwareProgressJsonl,
  VMWARE_STAGE_LABELS,
  type VMwareProgressSnapshot,
} from "@/lib/vmwareProgress";
import {
  expectedRedPlanFilename,
  MAX_VMWARE_RED_PLAN_BYTES,
  parseVmwareRedPlan,
  RED_SCENARIO_LABELS,
  type VMwareRedPlan,
} from "@/lib/vmwareRedPlan";

type LocalFileHandle = {
  getFile(): Promise<File>;
  isSameEntry?(other: LocalFileHandle): Promise<boolean>;
};
type LocalStopFileHandle = LocalFileHandle & {
  createWritable(): Promise<{ write(value: string): Promise<void>; close(): Promise<void> }>;
};
type LocalDirectoryHandle = {
  name: string;
  getFileHandle(name: string, options?: { create?: boolean }): Promise<LocalStopFileHandle>;
};
type BrowserWithFilePicker = Window & {
  showOpenFilePicker?: (options?: {
    multiple?: boolean;
    types?: Array<{ description: string; accept: Record<string, string[]> }>;
  }) => Promise<LocalFileHandle[]>;
  showDirectoryPicker?: (options?: {
    mode?: "read" | "readwrite";
  }) => Promise<LocalDirectoryHandle>;
};
const STAGES = ["preflight", "red", "zeek", "blue", "audit", "soc"] as const;
const STATUS_LABELS = {
  running: "Đang chạy",
  completed: "Đã hoàn thành phần mềm",
  skipped: "Bỏ qua",
  dry_run: "Kiểm tra khô",
} as const;
const COUNT_LABELS: Record<string, string> = {
  attempted_probes: "Số lượt thử kết nối",
  snapshot_flow_count: "Flow trong snapshot",
  research_candidate_count: "Ứng viên nghiên cứu",
  candidate_matches: "UID trùng khớp ứng viên",
  unmatched_attempts: "Lượt không khớp",
};

function LocalProgressView() {
  const [snapshot, setSnapshot] = useState<VMwareProgressSnapshot | null>(null);
  const [redPlan, setRedPlan] = useState<VMwareRedPlan | null>(null);
  const [redPlanError, setRedPlanError] = useState("");
  const [redPlanFilename, setRedPlanFilename] = useState("");
  const [error, setError] = useState("");
  const [filename, setFilename] = useState("");
  const [updated, setUpdated] = useState("");
  const [watching, setWatching] = useState(false);
  const [stopPrompt, setStopPrompt] = useState<{
    directory: LocalDirectoryHandle;
    target: LocalFileHandle;
    generation: number;
  } | null>(null);
  const [stopStatus, setStopStatus] = useState("");
  const handle = useRef<LocalFileHandle | null>(null);
  const seen = useRef("");
  const op = useRef(0);

  const applyFile = useCallback(async (file: File, generation: number) => {
    if (file.size > MAX_VMWARE_PROGRESS_BYTES) {
      throw new Error("Tệp vượt giới hạn 1 MiB.");
    }
    const signature = file.name + ":" + file.size + ":" + file.lastModified;
    if (signature === seen.current) return;
    const parsed = parseVMwareProgressJsonl(await file.text());
    if (generation !== op.current) return;
    setSnapshot(parsed);
    setFilename(file.name);
    setUpdated(new Date().toLocaleTimeString("vi-VN"));
    setError("");
    seen.current = signature;
  }, []);

  useEffect(() => {
    if (!watching || !handle.current) return;
    let disposed = false;
    const generation = op.current;
    const poll = async () => {
      if (disposed || !handle.current) return;
      try {
        const file = await handle.current.getFile();
        if (!disposed) await applyFile(file, generation);
      } catch {
        if (!disposed) {
          // Never leave a previously valid "completed" snapshot on-screen
          // after later bytes fail provenance/schema validation.
          setSnapshot(null);
          setRedPlan(null);
          setRedPlanFilename("");
          setRedPlanError("");
          setFilename("");
          setUpdated("");
          seen.current = "";
          setError("Tệp đang theo dõi không còn hợp lệ hoặc không thể đọc. Đã xóa toàn bộ tiến độ cũ và ngừng theo dõi.");
          setWatching(false);
          setStopPrompt(null);
          setStopStatus("");
          op.current += 1;
          handle.current = null;
        }
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 1500);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [watching, applyFile]);

  const importFile = async (file?: File) => {
    if (!file) return;
    op.current += 1;
    handle.current = null;
    setWatching(false);
    setStopPrompt(null);
    setStopStatus("");
    seen.current = "";
    setSnapshot(null);
    setRedPlan(null);
    setRedPlanFilename("");
    setRedPlanError("");
    setError("");
    try {
      await applyFile(file, op.current);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Không thể mở JSONL.");
    }
  };

  const startWatch = async () => {
    const pickerHost = window as BrowserWithFilePicker;
    const picker = pickerHost.showOpenFilePicker;
    if (!picker) {
      setError("Trình duyệt hiện tại không hỗ trợ theo dõi tệp cục bộ. Hãy dùng Chrome/Edge qua localhost hoặc chọn tệp thủ công.");
      return;
    }
    try {
      const files = await picker.call(pickerHost, {
        multiple: false,
        types: [{ description: "DA005 JSONL", accept: { "application/x-ndjson": [".jsonl"] } }],
      });
      if (files.length !== 1) return;
      op.current += 1;
      seen.current = "";
      setSnapshot(null);
      setRedPlan(null);
      setRedPlanFilename("");
      setRedPlanError("");
      setFilename("");
      setError("");
      handle.current = files[0];
      setStopPrompt(null);
      setStopStatus("");
      setWatching(true);
    } catch (reason) {
      // A user cancelling the browser picker is not an error.
      if (reason instanceof Error && reason.name !== "AbortError") {
        setError("Không thể cấp quyền đọc tệp JSONL.");
      }
    }
  };

  const reset = () => {
    op.current += 1;
    handle.current = null;
    seen.current = "";
    setWatching(false);
    setStopPrompt(null);
    setStopStatus("");
    setSnapshot(null);
    setRedPlan(null);
    setRedPlanFilename("");
    setRedPlanError("");
    setFilename("");
    setUpdated("");
    setError("");
  };

  // One file-picker action imports both private artifacts atomically.
  // Selection alone never executes VMware, writes local files or uploads data.
  const importSessionPair = async (files: File[]) => {
    if (files.length === 0) return;
    op.current += 1;
    const generation = op.current;
    handle.current = null;
    setWatching(false);
    setStopPrompt(null);
    setStopStatus("");
    seen.current = "";
    setSnapshot(null);
    setRedPlan(null);
    setRedPlanFilename("");
    setRedPlanError("");
    setFilename("");
    setUpdated("");
    setError("");
    try {
      if (files.length !== 2) {
        throw new Error("Chọn đúng hai tệp: một .jsonl và biên nhận .red-plan.json cùng tên phiên.");
      }
      const progressFiles = files.filter((file) => file.name.endsWith(".jsonl"));
      if (progressFiles.length !== 1) {
        throw new Error("Cặp tệp phải có đúng một nhật ký .jsonl.");
      }
      const progress = progressFiles[0];
      const expectedReceipt = expectedRedPlanFilename(progress.name);
      const receipt = files.find((file) => file.name === expectedReceipt);
      if (!receipt) {
        throw new Error("Biên nhận Red không khớp tên phiên JSONL.");
      }
      if (progress.size > MAX_VMWARE_PROGRESS_BYTES || receipt.size > MAX_VMWARE_RED_PLAN_BYTES) {
        throw new Error("Cặp tệp vượt giới hạn 1 MiB JSONL hoặc 4 KiB biên nhận Red.");
      }
      const [timelineText, receiptText] = await Promise.all([progress.text(), receipt.text()]);
      const parsedTimeline = parseVMwareProgressJsonl(timelineText);
      const parsedReceipt = parseVmwareRedPlan(receiptText);
      if (generation !== op.current) return;
      setSnapshot(parsedTimeline);
      setRedPlan(parsedReceipt);
      setFilename(progress.name);
      setRedPlanFilename(receipt.name);
      setUpdated(new Date().toLocaleTimeString("vi-VN"));
      seen.current = progress.name + ":" + progress.size + ":" + progress.lastModified;
    } catch (reason) {
      if (generation !== op.current) return;
      setError(reason instanceof Error ? reason.message : "Không thể nhập cặp tệp VMware.");
    }
  };

  const importRedPlan = async (file?: File) => {
    if (!file) return;
    const generation = op.current;
    setRedPlan(null);
    setRedPlanFilename("");
    setRedPlanError("");
    try {
      if (!snapshot || !filename) {
        throw new Error("Cần mở tệp JSONL của phiên trước khi nhập quyết định Red.");
      }
      if (file.name !== expectedRedPlanFilename(filename)) {
        throw new Error("Tên biên nhận Red không khớp tệp JSONL đang mở.");
      }
      if (file.size > MAX_VMWARE_RED_PLAN_BYTES) {
        throw new Error("Biên nhận Red vượt giới hạn 4 KiB.");
      }
      const parsed = parseVmwareRedPlan(await file.text());
      if (generation !== op.current) return;
      setRedPlan(parsed);
      setRedPlanFilename(file.name);
    } catch (reason) {
      if (generation !== op.current) return;
      setRedPlanError(reason instanceof Error ? reason.message : "Từ chối biên nhận Red.");
    }
  };

  // Explicit, two-step browser permission flow: NEVER writes a STOP marker
  // without a real user click. The selected directory must contain the exact
  // currently watched file handle; no arbitrary browser directory writes.
  const requestStop = async () => {
    if (!watching || !handle.current || snapshot?.terminal) {
      setError("Chỉ yêu cầu STOP khi đang theo dõi một phiên chưa kết thúc.");
      return;
    }
    const host = window as BrowserWithFilePicker;
    const picker = host.showDirectoryPicker;
    if (!picker) {
      setError("STOP từ giao diện cần Chrome/Edge trên localhost và quyền ghi thư mục riêng tư. Có thể tạo marker bằng PowerShell.");
      return;
    }
    const target = handle.current;
    const generation = op.current;
    try {
      const directory = await picker.call(host, { mode: "readwrite" });
      if (generation !== op.current || target !== handle.current || !watching) return;
      const file = await target.getFile();
      const matching = await directory.getFileHandle(file.name, { create: false });
      if (typeof matching.isSameEntry !== "function" ||
          !(await matching.isSameEntry(target))) {
        throw new Error("Thư mục STOP không chứa chính tệp JSONL đang theo dõi.");
      }
      if (generation !== op.current || target !== handle.current) return;
      setStopPrompt({ directory, target, generation });
      setStopStatus("");
      setError("");
    } catch (reason) {
      if (reason instanceof Error && reason.name === "AbortError") return;
      setStopPrompt(null);
      setError(reason instanceof Error && reason.message.includes("không chứa")
        ? reason.message
        : "Không xác nhận được quyền hoặc thư mục STOP. Chưa ghi tệp.");
    }
  };

  const confirmStop = async () => {
    const pending = stopPrompt;
    if (!pending || !watching || snapshot?.terminal ||
        pending.generation !== op.current || pending.target !== handle.current) {
      setStopPrompt(null);
      setError("Phiên hoặc tệp đang theo dõi đã thay đổi. Yêu cầu STOP bị hủy.");
      return;
    }
    try {
      // An existing marker already represents a STOP request. Do not modify it.
      let exists = false;
      try {
        await pending.directory.getFileHandle("DA005_STOP.flag", { create: false });
        exists = true;
      } catch (reason) {
        if (!(reason instanceof Error) || reason.name !== "NotFoundError") throw reason;
      }
      if (!exists) {
        const marker = await pending.directory.getFileHandle("DA005_STOP.flag", { create: true });
        const writer = await marker.createWritable();
        await writer.write("");
        await writer.close();
      }
      setStopPrompt(null);
      setStopStatus(exists
        ? "Marker STOP đã có sẵn. Python sẽ xử lý tại điểm kiểm tra tiếp theo nếu phiên đang chạy."
        : "Đã tạo DA005_STOP.flag. Đây là yêu cầu dừng hợp tác, chưa xác nhận Python đã dừng.");
      setError("");
    } catch {
      setStopPrompt(null);
      setError("Không ghi được marker STOP. Phiên có thể vẫn đang chạy; kiểm tra trực tiếp trên Windows.");
    }
  };

  const latest = useMemo(() => {
    const map = new Map<string, NonNullable<VMwareProgressSnapshot>["events"][number]>();
    for (const event of snapshot?.events ?? []) map.set(event.stage, event);
    return map;
  }, [snapshot]);

  const terminal = snapshot?.terminal ?? null;
  const resolvedStages = STAGES.filter((stage) => {
    const status = latest.get(stage)?.status;
    return status === "completed" || status === "skipped" || status === "dry_run";
  }).length;
  const redAttempts = latest.get("red")?.counts.attempted_probes;
  const zeekFlows = latest.get("zeek")?.counts.snapshot_flow_count;
  const blueStage = latest.get("blue");
  const blueCandidates = blueStage?.status === "skipped"
    ? "Không chạy"
    : (blueStage?.counts.research_candidate_count ?? "—");
  const candidateMatches = latest.get("audit")?.counts.candidate_matches;
  const sessionStats = [
    { label: "Lượt thử Red lành tính", value: redAttempts ?? "—" },
    { label: "Flow Zeek snapshot", value: zeekFlows ?? "—" },
    { label: "Ứng viên nghiên cứu Blue", value: blueCandidates },
    { label: "Khớp UID ứng viên", value: candidateMatches ?? "—" },
  ] as const;
  return (
    <AppShell
      title="VMware · Local Evidence Timeline"
      breadcrumb="Sentinel Lab / VMware Stage Viewer"
      provenanceTag="OPERATOR-ASSISTED · CHƯA XÁC MINH LIVE AI"
    >
      <div className="space-y-5">
        <section className="rounded-xl border border-amber-700/40 bg-amber-950/20 p-4">
          <h2 className="text-sm font-semibold text-amber-200">Chỉ xem tiến độ cục bộ · Không phải bằng chứng phát hiện tấn công</h2>
          <p className="mt-2 text-xs leading-6 text-slate-300">
            Màn hình này đọc tệp JSONL do chương trình VMware Stepwise tạo trên laptop. Không tự chạy Red Team,
            không kết nối máy ảo và không đưa nội dung tệp lên API. Chỉ khi người vận hành chọn đúng thư mục
            và xác nhận STOP, trình duyệt mới ghi marker trống DA005_STOP.flag tại đó.
            Trạng thái hoàn thành chỉ xác nhận chương trình
            đã hoàn thành bước xử lý, chưa chứng minh cô lập mạng Host-only, tính xác thực PCAP, AI phát hiện tấn công hoặc SOC live.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Luồng SYNTHETIC REPLAY ở trang Automated Lab được giữ tách biệt hoàn toàn với màn hình này.
          </p>
        </section>
        <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <h2 className="text-sm font-semibold text-slate-100">Nguồn sự kiện JSONL</h2>
          <p className="mt-2 text-xs text-slate-400">
            Với Chromium trên localhost, chọn “Theo dõi tệp” để cập nhật khi PowerShell ghi thêm sự kiện. Hoặc dùng “Mở cặp JSONL + Red” để nhập đồng thời hai tệp của cùng một phiên; lựa chọn này chỉ đọc một lần, không tự theo dõi.
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <label className="cursor-pointer rounded-lg border border-slate-600 px-3 py-2 text-xs font-semibold text-slate-100 hover:bg-slate-800">
              Mở tệp JSONL
              <input
                aria-label="Mở tệp JSONL VMware"
                type="file"
                accept=".jsonl,.txt"
                className="sr-only"
                onChange={(event) => {
                  const file = event.currentTarget.files?.[0];
                  void importFile(file);
                  event.currentTarget.value = "";
                }}
              />
            </label>
            <label className="cursor-pointer rounded-lg border border-slate-600 px-3 py-2 text-xs font-semibold text-slate-100 hover:bg-slate-800">
              Mở cặp JSONL + Red
              <input
                aria-label="Mở cặp JSONL và biên nhận Red"
                type="file"
                accept=".jsonl,.json"
                multiple
                className="sr-only"
                onChange={(event) => {
                  const files = Array.from(event.currentTarget.files ?? []);
                  void importSessionPair(files);
                  event.currentTarget.value = "";
                }}
              />
            </label>
            <button type="button" onClick={() => void startWatch()} disabled={watching}
              className="rounded-lg bg-blue-600 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-50">
              {watching ? "Đang theo dõi tệp" : "Theo dõi tệp đang ghi"}
            </button>
            <button type="button" onClick={() => void requestStop()}
              disabled={!watching || Boolean(snapshot?.terminal) || Boolean(stopStatus)}
              className="rounded-lg border border-red-700 px-3 py-2 text-xs font-semibold text-red-200 hover:bg-red-950 disabled:opacity-40">
              Yêu cầu STOP qua tệp
            </button>
            <button type="button" onClick={reset}
              className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:bg-slate-800">
              Đóng phiên
            </button>
          </div>
          {stopPrompt && (
            <div role="group" aria-label="Xác nhận yêu cầu STOP" className="mt-3 space-y-2 rounded-lg border border-red-700/70 p-3 text-xs text-slate-200">
              <p>Thư mục đã đối chiếu với tệp đang theo dõi: {stopPrompt.directory.name}.
                Xác nhận tạo DA005_STOP.flag? Python chỉ kiểm tra ở ranh giới giữa các thao tác;
                một socket hoặc SCP đang chờ sẽ không bị ngắt tức thời.</p>
              <div className="flex flex-wrap gap-2">
                <button type="button" onClick={() => void confirmStop()}
                  className="rounded-md bg-red-800 px-3 py-2 font-semibold text-white hover:bg-red-700">
                  Xác nhận gửi STOP
                </button>
                <button type="button" onClick={() => setStopPrompt(null)}
                  className="rounded-md border border-slate-600 px-3 py-2">
                  Hủy yêu cầu STOP
                </button>
              </div>
            </div>
          )}
          {stopStatus && <p role="status" className="mt-3 text-xs text-amber-200">{stopStatus}</p>}
          {error && <p role="alert" className="mt-3 rounded-lg border border-red-700 bg-red-950/40 p-3 text-xs text-red-200">{error}</p>}
          <div className="mt-3 grid gap-2 text-xs text-slate-400 sm:grid-cols-3">
            <p>Tệp: <span className="break-all text-slate-200">{filename || "Chưa chọn"}</span></p>
            <p>Đọc lần cuối: <span className="text-slate-200">{updated || "—"}</span></p>
            <p>Trạng thái phiên: <span className="font-semibold text-slate-100">
              {terminal === "completed" ? "Phần mềm kết thúc" :
                terminal === "refused" ? "Đã từ chối / gặp lỗi" :
                terminal === "dry_run" ? "Dry-run" : watching ? "Đang theo dõi" : "Chưa có kết quả cuối"}
            </span></p>
          </div>
          {snapshot?.pendingLastLine &&
            <p className="mt-2 text-xs text-amber-300">Có một dòng đang ghi dở; chưa được tính là sự kiện hoàn thành.</p>}
        </section>

        <section aria-labelledby="vmware-red-policy" className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <h2 id="vmware-red-policy" className="text-sm font-semibold text-slate-100">
            Red Team · Quyết định chọn kịch bản offline
          </h2>
          <p className="mt-2 text-xs leading-5 text-slate-400">
            Chỉ profile v2 mới có biên nhận quyết định UCB1 hoặc seeded-random. Tệp được đọc ngay trong
            trình duyệt, không tải lên API. Lựa chọn thuật toán là một nhãn kịch bản kết nối lành tính,
            không phải bằng chứng AI tấn công, Blue phát hiện hay kết quả mạng thực tế.
          </p>
          <label className="mt-3 inline-block cursor-pointer rounded-lg border border-slate-600 px-3 py-2 text-xs font-semibold text-slate-100 hover:bg-slate-800">
            Mở biên nhận Red Team
            <input aria-label="Mở biên nhận Red Team" type="file" accept=".json"
              className="sr-only"
              onChange={(event) => {
                const file = event.currentTarget.files?.[0];
                void importRedPlan(file);
                event.currentTarget.value = "";
              }} />
          </label>
          {redPlanError &&
            <p role="alert" className="mt-3 rounded-md border border-red-700 bg-red-950/40 p-3 text-xs text-red-200">
              {redPlanError}
            </p>}
          {redPlan ? (
            <div className="mt-3 grid gap-3 rounded-lg border border-slate-700 p-3 text-xs text-slate-300 md:grid-cols-2">
              <p>Kịch bản đã chọn: <span className="font-semibold text-slate-100">
                {RED_SCENARIO_LABELS[redPlan.selected_scenario_id]}
              </span></p>
              <p>Thuật toán: <span className="font-semibold text-slate-100">
                {redPlan.strategy === "ucb1" ? "UCB1" : "Seeded random"}
              </span></p>
              <p>Số phản hồi nhập tay: <span className="font-mono text-slate-100">{redPlan.feedback_count}</span></p>
              <p>Seed: <span className="font-mono text-slate-100">{redPlan.seed}</span></p>
              <p className="break-all md:col-span-2">
                Biên nhận: {redPlanFilename}
              </p>
              <p className="break-all md:col-span-2">
                SHA-256 profile tự khai: <span className="font-mono text-slate-100">{redPlan.profile_sha256}</span>
              </p>
              <p className="md:col-span-2 text-amber-200">
                Biên nhận chưa được xác minh độc lập bằng tệp profile. Phản hồi nhập tay không phải
                nhãn ground truth; việc chọn kịch bản không xác nhận nó đã được thực thi.
              </p>
            </div>
          ) : (
            <p className="mt-3 text-xs text-slate-500">
              {snapshot
                ? "Chưa có biên nhận Red Team phù hợp với tên tệp JSONL này."
                : "Chưa mở phiên JSONL. Không có kết quả UCB1 để hiển thị."}
            </p>
          )}
        </section>

        <section aria-labelledby="vmware-kpis" className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 id="vmware-kpis" className="text-sm font-semibold text-slate-100">
              Thông số tiến độ từ JSONL cục bộ
            </h2>
            <p className="text-xs font-mono text-slate-300">
              {resolvedStages}/{STAGES.length} giai đoạn có kết quả
            </p>
          </div>
          <div role="progressbar" aria-label="Số giai đoạn phần mềm có kết quả"
            aria-valuemin={0} aria-valuemax={STAGES.length} aria-valuenow={resolvedStages}
            className="mt-3 h-2 overflow-hidden rounded-full bg-slate-800">
            <div className="h-full bg-blue-500 transition-[width] duration-300"
              style={{ width: `${(resolvedStages / STAGES.length) * 100}%` }} />
          </div>
          <div className="mt-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
            {sessionStats.map((stat) => (
              <div key={stat.label} className="rounded-lg border border-slate-800 bg-slate-950/40 p-3">
                <p className="text-[11px] text-slate-400">{stat.label}</p>
                <p className="mt-2 font-mono text-lg font-semibold tabular-nums text-slate-100">
                  {stat.value}
                </p>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs leading-5 text-slate-400">
            Các chỉ số này chỉ phản ánh dữ liệu sự kiện phần mềm đã đọc.
            Số lượt thử, số flow, ứng viên Blue và UID khớp không phải số tấn công được xác minh,
            độ chính xác mô hình hay cảnh báo SOC đang hoạt động.
          </p>
        </section>

        <section aria-labelledby="vmware-stages" className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <h2 id="vmware-stages" className="text-sm font-semibold text-slate-100">Quy trình kiểm thử từng giai đoạn</h2>
          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {STAGES.map((stage) => {
              const info = latest.get(stage);
              return (
                <article key={stage} className="min-w-0 rounded-lg border border-slate-700 bg-slate-950/40 p-3">
                  <h3 className="text-xs font-semibold text-slate-100">{VMWARE_STAGE_LABELS[stage]}</h3>
                  <p className="mt-2 text-xs text-slate-300">
                    {info ? STATUS_LABELS[info.status] : "Chưa có sự kiện"}
                  </p>
                  <p className="mt-1 font-mono text-[11px] text-slate-500">
                    {info ? new Date(info.observed_at_utc).toLocaleTimeString("vi-VN") : "—"}
                  </p>
                  {info && Object.entries(info.counts).length > 0 &&
                    <div className="mt-3 space-y-1 border-t border-slate-800 pt-2">
                      {Object.entries(info.counts).map(([key, value]) =>
                        <p key={key} className="flex justify-between gap-3 text-[11px] text-slate-400">
                          <span>{COUNT_LABELS[key]}</span><span className="font-mono text-slate-100">{value}</span>
                        </p>
                      )}
                    </div>}
                </article>
              );
            })}
          </div>
        </section>

        <section aria-labelledby="vmware-events" className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <h2 id="vmware-events" className="text-sm font-semibold text-slate-100">
            Nhật ký tiến độ đã kiểm tra cấu trúc ({snapshot?.events.length ?? 0} sự kiện)
          </h2>
          <ol className="mt-3 max-h-80 space-y-2 overflow-y-auto" aria-live="polite">
            {!snapshot?.events.length && <li className="text-xs text-slate-400">Chưa có sự kiện hợp lệ từ tệp cục bộ.</li>}
            {(snapshot?.events ?? []).map((event) =>
              <li key={event.seq} className="grid gap-1 border-b border-slate-800 pb-2 text-xs text-slate-300 sm:grid-cols-[55px_115px_1fr]">
                <span className="font-mono text-slate-500">#{event.seq}</span>
                <span className="font-mono text-slate-400">{new Date(event.observed_at_utc).toLocaleTimeString("vi-VN")}</span>
                <span>{VMWARE_STAGE_LABELS[event.stage]} — {STATUS_LABELS[event.status]}</span>
              </li>
            )}
          </ol>
        </section>
        <p className="text-xs leading-5 text-slate-500">
          Kiểm tra JSONL chỉ xác minh cấu trúc dữ liệu và các tuyên bố giới hạn; không xác minh SHA-256 của capture.
          Sau kiểm thử thật, cần chạy công cụ audit snapshot và đối chiếu ảnh cấu hình VMnet, Zeek interface, PCAP và log gốc.
        </p>
      </div>
    </AppShell>
  );
}

export default function VMwareProgressPage() {
  return <LocalProgressView />;
}
