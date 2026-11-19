"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AppShell } from "@/components/AppShell";
import {
  MAX_VMWARE_PROGRESS_BYTES,
  parseVMwareProgressJsonl,
  VMWARE_STAGE_LABELS,
  type VMwareProgressSnapshot,
} from "@/lib/vmwareProgress";

type LocalFileHandle = { getFile(): Promise<File> };
type BrowserWithFilePicker = Window & {
  showOpenFilePicker?: (options?: {
    multiple?: boolean;
    types?: Array<{ description: string; accept: Record<string, string[]> }>;
  }) => Promise<LocalFileHandle[]>;
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
  const [error, setError] = useState("");
  const [filename, setFilename] = useState("");
  const [updated, setUpdated] = useState("");
  const [watching, setWatching] = useState(false);
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
          setError("Không thể tiếp tục đọc tệp hoặc nội dung JSONL không hợp lệ. Đã ngừng theo dõi.");
          setWatching(false);
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
    seen.current = "";
    setSnapshot(null);
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
      setError("");
      handle.current = files[0];
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
    setSnapshot(null);
    setFilename("");
    setUpdated("");
    setError("");
  };

  const latest = useMemo(() => {
    const map = new Map<string, NonNullable<VMwareProgressSnapshot>["events"][number]>();
    for (const event of snapshot?.events ?? []) map.set(event.stage, event);
    return map;
  }, [snapshot]);

  const terminal = snapshot?.terminal ?? null;
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
            không kết nối máy ảo và không đưa nội dung tệp lên API. Trạng thái hoàn thành chỉ xác nhận chương trình
            đã hoàn thành bước xử lý, chưa chứng minh cô lập mạng Host-only, tính xác thực PCAP, AI phát hiện tấn công hoặc SOC live.
          </p>
          <p className="mt-2 text-xs text-slate-400">
            Luồng SYNTHETIC REPLAY ở trang Automated Lab được giữ tách biệt hoàn toàn với màn hình này.
          </p>
        </section>
        <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <h2 className="text-sm font-semibold text-slate-100">Nguồn sự kiện JSONL</h2>
          <p className="mt-2 text-xs text-slate-400">
            Với Chromium trên localhost, chọn “Theo dõi tệp” để cập nhật khi PowerShell ghi thêm sự kiện. Nếu không hỗ trợ, chọn tệp thủ công sau khi chạy.
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
            <button type="button" onClick={() => void startWatch()} disabled={watching}
              className="rounded-lg bg-blue-600 px-3 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-50">
              {watching ? "Đang theo dõi tệp" : "Theo dõi tệp đang ghi"}
            </button>
            <button type="button" onClick={reset}
              className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 hover:bg-slate-800">
              Đóng phiên
            </button>
          </div>
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
