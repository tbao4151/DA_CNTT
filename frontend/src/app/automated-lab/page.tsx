"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { AppShell } from "@/components/AppShell";
import { API_BASE_URL } from "@/lib/api";

type Stage = "red" | "zeek" | "blue" | "soc" | "system";
type Status = "running" | "completed" | "stopped" | "failed";
type Strategy = "ucb1" | "random";

type LiveEvent = {
  seq: number;
  time: string;
  stage: Stage;
  message: string;
  details: Record<string, unknown>;
  source: "synthetic_replay";
};

type LiveSession = {
  session_id: string;
  status: Status;
  mode: "synthetic_replay";
  strategy: Strategy;
  rounds: number;
  current_round: number;
  started_at: string;
  finished_at: string | null;
  event_count: number;
  events: LiveEvent[];
  provenance: {
    source: string;
    network_execution: boolean;
    vmware_connected: boolean;
    ai_detection_executed: boolean;
    verified_attack_events: number;
    verified_ai_alerts: number;
    fixture_flows_per_round: number;
  };
};

const STAGES: Array<{ stage: Stage; label: string; color: string }> = [
  { stage: "red", label: "Red Team · Planner", color: "text-rose-300" },
  { stage: "zeek", label: "Zeek · Synthetic Replay", color: "text-amber-300" },
  { stage: "blue", label: "Blue Team · Inference OFF", color: "text-blue-300" },
  { stage: "soc", label: "SOC · Audit Trail", color: "text-emerald-300" },
];

async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(API_BASE_URL + path, { cache: "no-store", ...init });
  } catch {
    throw new Error("Không kết nối được FastAPI. Hãy khởi động start_backend.ps1.");
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(
      typeof body.detail === "string" ? body.detail : "HTTP " + response.status
    );
  }
  return (await response.json()) as T;
}

const VALID_STAGES: readonly Stage[] = ["red", "zeek", "blue", "soc", "system"];

function isSyntheticEvent(value: unknown): value is LiveEvent {
  if (typeof value !== "object" || value === null) return false;
  const event = value as Partial<LiveEvent>;
  return (
    event.source === "synthetic_replay" &&
    Number.isSafeInteger(event.seq) && Number(event.seq) >= 0 &&
    typeof event.time === "string" && !Number.isNaN(Date.parse(event.time)) &&
    typeof event.stage === "string" && VALID_STAGES.includes(event.stage as Stage) &&
    typeof event.message === "string" &&
    typeof event.details === "object" && event.details !== null &&
    !Array.isArray(event.details) &&
    (event.stage !== "zeek" ||
      (Number.isSafeInteger(event.details.sample_flow_count) &&
        Number(event.details.sample_flow_count) >= 0)) &&
    (event.details.round === undefined ||
      (Number.isSafeInteger(event.details.round) && Number(event.details.round) >= 1))
  );
}

function assertSyntheticSession(value: LiveSession): LiveSession {
  // JSON is untrusted at runtime even when apiRequest has a TypeScript type.
  // Validate the envelope before accessing nested provenance fields.
  if (
    typeof value !== "object" || value === null ||
    typeof value.session_id !== "string" || !value.session_id ||
    !["running", "completed", "stopped", "failed"].includes(value.status) ||
    typeof value.provenance !== "object" || value.provenance === null ||
    Array.isArray(value.provenance) ||
    value.mode !== "synthetic_replay" ||
    !["ucb1", "random"].includes(value.strategy) ||
    typeof value.started_at !== "string" || Number.isNaN(Date.parse(value.started_at)) ||
    !Number.isSafeInteger(value.provenance.fixture_flows_per_round) ||
    value.provenance.fixture_flows_per_round < 0 ||
    value.provenance.source !== "hardcoded_synthetic_zeek_fixture" ||
    value.provenance.network_execution !== false ||
    value.provenance.vmware_connected !== false ||
    value.provenance.ai_detection_executed !== false ||
    value.provenance.verified_attack_events !== 0 ||
    value.provenance.verified_ai_alerts !== 0 ||
    !Array.isArray(value.events) ||
    value.events.some((event, index) => !isSyntheticEvent(event) || event.seq !== index + 1) ||
    !Number.isSafeInteger(value.event_count) || value.event_count !== value.events.length ||
    !Number.isSafeInteger(value.rounds) || value.rounds < 1 ||
    !Number.isSafeInteger(value.current_round) || value.current_round < 0 ||
    value.current_round > value.rounds ||
    (value.status === "running" && value.finished_at !== null) ||
    (value.status !== "running" &&
      (typeof value.finished_at !== "string" || Number.isNaN(Date.parse(value.finished_at))))
  ) {
    throw new Error("Phản hồi session không khớp hợp đồng SYNTHETIC REPLAY. Từ chối hiển thị để tránh nhầm với dữ liệu live.");
  }
  return value;
}

type SyntheticReport = LiveSession & {
  report_kind: "synthetic_replay_telemetry_only";
  verified_detection_metrics: null;
  real_network_flows: 0;
  verified_ai_alerts: 0;
  limitations: string[];
};

function assertSyntheticReport(value: SyntheticReport, sessionId: string): SyntheticReport {
  assertSyntheticSession(value);
  if (
    value.session_id !== sessionId ||
    value.report_kind !== "synthetic_replay_telemetry_only" ||
    value.verified_detection_metrics !== null ||
    value.real_network_flows !== 0 ||
    value.verified_ai_alerts !== 0 ||
    !Array.isArray(value.limitations) ||
    !value.limitations.every((item) => typeof item === "string")
  ) {
    throw new Error("Báo cáo không khớp hợp đồng SYNTHETIC REPLAY. Đã chặn tải xuống.");
  }
  return value;
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString("vi-VN");
}

export default function AutomatedLabPage() {
  const [session, setSession] = useState<LiveSession | null>(null);
  const [rounds, setRounds] = useState(2);
  const [strategy, setStrategy] = useState<Strategy>("ucb1");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [streamStatus, setStreamStatus] = useState("Chưa kết nối");
  const [selectedStep, setSelectedStep] = useState<"red" | "zeek" | "blue" | "soc">("red");

  const refresh = useCallback(async (sessionId: string) => {
    const next = await apiRequest<LiveSession>(
      "/live-sessions/" + encodeURIComponent(sessionId)
    );
    setSession(assertSyntheticSession(next));
  }, []);

  useEffect(() => {
    if (!session?.session_id || session.status !== "running") return;
    const sessionId = session.session_id;
    let active = true;
    let provenanceRejected = false;
    const source = new EventSource(
      API_BASE_URL + "/live-sessions/" + encodeURIComponent(sessionId) + "/events"
    );
    setStreamStatus("Đang nhận sự kiện từ FastAPI (SSE)");

    source.addEventListener("progress", (message) => {
      if (!active) return;
      let event: LiveEvent;
      try {
        event = JSON.parse((message as MessageEvent).data) as LiveEvent;
        if (!isSyntheticEvent(event)) throw new Error("Sự kiện SSE không hợp lệ");
      } catch {
        provenanceRejected = true;
        source.close();
        setSession(null);
        setStreamStatus("SSE chứa dữ liệu không hợp lệ · Đã ngắt stream");
        setError("Sự kiện không có provenance SYNTHETIC REPLAY hợp lệ. Không hiển thị.");
        return;
      }
      setSession((prev) => {
        if (!prev || prev.session_id !== sessionId) return prev;
        if (prev.status !== "running" || prev.events.some((item) => item.seq === event.seq)) return prev;
        // SSE can be duplicated or arrive after a newer polling snapshot.
        // On gaps, leave the state unchanged; polling restores the authoritative snapshot.
        if (event.seq !== prev.events.length + 1) return prev;
        return {
          ...prev,
          event_count: prev.event_count + 1,
          current_round: Number(event.details.round ?? prev.current_round),
          events: [...prev.events, event],
        };
      });
    });

    source.addEventListener("complete", () => {
      source.close();
      if (active) {
        setStreamStatus("Phiên kết thúc · SSE đã đóng");
        void refresh(sessionId).catch((err) => setError(err instanceof Error ? err.message : "Không đồng bộ được phiên"));
      }
    });
    source.onerror = () => {
      source.close();
      if (active) setStreamStatus("SSE ngắt kết nối · Đang đồng bộ bằng polling");
    };

    // Fallback also resolves terminal state if a final SSE event was lost.
    const timer = window.setInterval(() => {
      if (active && !provenanceRejected) void refresh(sessionId).catch((err) => {
        if (!active) return;
        setSession(null);
        setStreamStatus("Đã dừng đồng bộ do phản hồi không hợp lệ");
        setError(err instanceof Error ? err.message : "Không xác minh được dữ liệu phiên. Đã ẩn session.");
      });
    }, 1800);

    return () => {
      active = false;
      source.close();
      window.clearInterval(timer);
    };
  }, [session?.session_id, session?.status, refresh]);

  const start = async () => {
    setBusy(true);
    setError(null);
    setSession(null);
    setStreamStatus("Chưa kết nối");
    try {
      const started = await apiRequest<LiveSession>("/live-sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: "synthetic_replay", strategy, rounds }),
      });
      setSession(assertSyntheticSession(started));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể tạo phiên.");
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      const stopped = await apiRequest<LiveSession>(
        "/live-sessions/" + encodeURIComponent(session.session_id) + "/stop",
        { method: "POST" }
      );
      setSession(assertSyntheticSession(stopped));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể dừng phiên.");
    } finally {
      setBusy(false);
    }
  };

  const downloadReport = async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      const response = await apiRequest<SyntheticReport>(
        "/live-sessions/" + encodeURIComponent(session.session_id) + "/report"
      );
      const report = assertSyntheticReport(response, session.session_id);
      const blob = new Blob([JSON.stringify(report, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "DA005_synthetic_replay_" + session.session_id.slice(0, 8) + ".json";
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể xuất báo cáo.");
    } finally {
      setBusy(false);
    }
  };

  const flows = useMemo(
    () => session?.events
      .filter((item) => item.stage === "zeek")
      .reduce((sum, item) => sum + Number(item.details.sample_flow_count ?? 0), 0) ?? 0,
    [session?.events]
  );

  const selectedEvidence = useMemo(
    () => session?.events.filter((event) => event.stage === selectedStep) ?? [],
    [session?.events, selectedStep]
  );

  const latestFor = (stage: Stage) =>
    [...(session?.events ?? [])].reverse().find((item) => item.stage === stage);

  return (
    <AppShell
      title="Autonomous Lab · Dual-AI Monitor"
      breadcrumb="Sentinel Lab / Automated Lab"
      provenanceTag="SYNTHETIC REPLAY · EXECUTION OFF"
    >
      <div className="space-y-5">
        <section className="rounded-xl border border-amber-700/50 bg-amber-950/30 p-4">
          <p className="text-sm font-semibold text-amber-200">
            Giai đoạn tích hợp đầu tiên — SYNTHETIC REPLAY, KHÔNG PHẢI LIVE ATTACK
          </p>
          <p className="mt-2 text-xs leading-6 text-amber-100/80">
            Chế độ này chạy một vòng điều phối sự kiện trên fixture Zeek tổng hợp.
            Red Team chỉ chọn nhãn kịch bản; không điều khiển VMware, không phát lưu lượng.
            Blue Team chưa suy luận trên Zeek nên không có cảnh báo AI hoặc độ chính xác thật.
            Timeline được nhận liên tục qua SSE từ FastAPI, không phải hoạt ảnh giả.
          </p>
        </section>

        <section className="flex flex-wrap items-end justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="flex flex-wrap items-end gap-3">
            <label className="block text-xs text-slate-300">
              Chiến lược chọn nhãn
              <select
                value={strategy}
                onChange={(e) => setStrategy(e.target.value as Strategy)}
                disabled={session?.status === "running"}
                className="mt-1 block rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              >
                <option value="ucb1">UCB1 (chưa có feedback)</option>
                <option value="random">Seeded Random</option>
              </select>
            </label>
            <label className="block text-xs text-slate-300">
              Số vòng replay
              <select
                value={rounds}
                onChange={(e) => setRounds(Number(e.target.value))}
                disabled={session?.status === "running"}
                className="mt-1 block rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-white"
              >
                {[1, 2, 3, 4].map((value) => (
                  <option key={value} value={value}>{value}</option>
                ))}
              </select>
            </label>
          </div>
          <div className="flex flex-wrap gap-2">
            {session?.status === "running" ? (
              <button
                type="button"
                onClick={() => void stop()}
                disabled={busy}
                className="rounded-lg bg-red-700 px-4 py-2 text-sm font-semibold text-white hover:bg-red-600 disabled:opacity-50"
              >
                Dừng phiên
              </button>
            ) : (
              <button
                type="button"
                onClick={() => void start()}
                disabled={busy}
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
              >
                {busy ? "Đang khởi tạo..." : "Bắt đầu replay tự động"}
              </button>
            )}
            {session && (
              <button
                type="button"
                onClick={() => void downloadReport()}
                disabled={busy}
                className="rounded-lg border border-slate-600 px-4 py-2 text-sm font-semibold text-slate-100 hover:bg-slate-800 disabled:opacity-50"
              >
                Xuất báo cáo JSON
              </button>
            )}
          </div>
        </section>

        {error && <div role="alert" className="rounded-lg border border-red-700 bg-red-950/40 p-3 text-sm text-red-200">{error}</div>}

        <div className="grid gap-3 sm:grid-cols-4">
          {[
            ["Trạng thái", session?.status ?? "ready"],
            ["Vòng kiểm thử", session ? session.current_round + " / " + session.rounds : "0 / " + rounds],
            ["Synthetic flows đã phát lại", String(flows)],
            ["Cảnh báo AI xác minh", String(session?.provenance.verified_ai_alerts ?? 0)],
          ].map(([label, value]) => (
            <div key={label} className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
              <p className="text-xs text-slate-400">{label}</p>
              <p className="mt-2 break-words font-mono text-xl font-semibold text-slate-100">{value}</p>
            </div>
          ))}
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          <section className="rounded-xl border border-rose-800/60 bg-rose-950/20 p-4">
            <h2 className="text-sm font-bold uppercase tracking-wide text-rose-300">Red Team AI · Planner</h2>
            <p className="mt-1 text-xs text-slate-400">Chọn nhãn từ catalog; chưa thực thi mạng, chưa có feedback xác minh.</p>
            <div className="mt-4 rounded-lg border border-rose-900/60 bg-slate-950/50 p-3">
              <p className="text-xs text-slate-400">Quyết định mới nhất</p>
              <p className="mt-2 text-sm text-slate-100">
                {String(latestFor("red")?.details.scenario_title ?? "Chưa chọn kịch bản")}
              </p>
              <p className="mt-2 text-xs leading-5 text-slate-400">
                {String(latestFor("red")?.details.rationale ?? "Không có quyết định")}
              </p>
            </div>
          </section>
          <section className="rounded-xl border border-blue-800/60 bg-blue-950/20 p-4">
            <h2 className="text-sm font-bold uppercase tracking-wide text-blue-300">Blue Team AI · Detection</h2>
            <p className="mt-1 text-xs text-slate-400">Model UNSW-NB15 chưa được áp dụng trực tiếp cho Zeek conn.log.</p>
            <div className="mt-4 rounded-lg border border-blue-900/60 bg-slate-950/50 p-3">
              <p className="text-xs text-slate-400">Trạng thái suy luận</p>
              <p className="mt-2 text-sm font-semibold text-amber-200">INFERENCE OFF · CHƯA CÓ KẾT QUẢ AI THẬT</p>
              <p className="mt-2 text-xs text-slate-400">
                {latestFor("blue")?.message ?? "Chưa đến bước Blue Team trong vòng replay."}
              </p>
            </div>
          </section>
        </div>

        <section aria-labelledby="stepwise-title" className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <h2 id="stepwise-title" className="text-sm font-semibold text-slate-100">Step-by-Step · Kiểm tra bằng chứng theo giai đoạn</h2>
          <p className="mt-2 text-xs leading-5 text-slate-400">
            Chỉ duyệt sự kiện đã nhận từ API. Không kích hoạt Red Team, Zeek, Blue Team hoặc SOC thật.
            Các bước không có dữ liệu được ghi là chưa có bằng chứng, không tự sinh kết quả.
          </p>
          <div role="group" aria-label="Chọn giai đoạn để xem sự kiện" className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {STAGES.map(({ stage, label }) => (
              <button
                key={stage}
                type="button"
                aria-pressed={selectedStep === stage}
                onClick={() => setSelectedStep(stage as "red" | "zeek" | "blue" | "soc")}
                className={"min-w-0 rounded-md border px-2 py-2 text-left text-xs focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-400 " +
                  (selectedStep === stage ? "border-blue-400 bg-blue-950 text-white" : "border-slate-700 text-slate-300 hover:bg-slate-800")}
              >
                {label}
                <span className="mt-1 block font-mono text-[11px]">
                  {session?.events.filter((event) => event.stage === stage).length ?? 0} sự kiện
                </span>
              </button>
            ))}
          </div>
          <div aria-live="polite" className="mt-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
            <p className="text-xs font-semibold text-amber-200">Nguồn: SYNTHETIC REPLAY · VMware chưa xác minh</p>
            {selectedEvidence.length === 0 ? (
              <p className="mt-2 text-sm text-slate-400">Chưa có sự kiện cho giai đoạn này. Không có bằng chứng để trình bày.</p>
            ) : (
              <ol className="mt-2 max-h-52 space-y-2 overflow-y-auto">
                {selectedEvidence.map((event) => (
                  <li key={event.seq} className="border-b border-slate-800 pb-2 text-xs text-slate-200">
                    <span className="font-mono text-slate-400">#{event.seq} · {formatTime(event.time)} · </span>
                    {event.message}
                    <p className="mt-1 break-all font-mono text-[11px] text-slate-400">
                      {event.stage === "zeek" ? "Synthetic fixture flows: " + String(event.details.sample_flow_count ?? "không có") :
                        event.stage === "red" ? "Scenario label: " + String(event.details.scenario_id ?? "không có") :
                        event.stage === "blue" ? "Model inference: OFF" : "Verified SOC cases: 0"}
                    </p>
                  </li>
                ))}
              </ol>
            )}
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Đường kiểm thử VMware giai đoạn 1 chạy riêng bằng CLI read-only; không nhập kết quả SSH/SCP hoặc research scoring vào phiên SSE synthetic này.
            Xem docs/VMWARE_ZEEK_RESEARCH_BRIDGE.md.
          </p>
        </section>

        <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold text-slate-100">Live Event Timeline · SSE</h2>
            <span className="text-xs text-slate-400">{session ? streamStatus : "Chưa có phiên"}</span>
          </div>
          <div aria-live="polite" className="mt-3 max-h-96 space-y-2 overflow-y-auto">
            {!session?.events.length && <p className="py-8 text-center text-sm text-slate-400">Nhấn Bắt đầu để theo dõi từng sự kiện của phiên replay.</p>}
            {(session?.events ?? []).map((event) => {
              const info = STAGES.find((item) => item.stage === event.stage);
              return (
                <article key={event.seq} className="grid gap-2 rounded-lg border border-slate-800 bg-slate-950/50 p-3 sm:grid-cols-[84px_140px_1fr] sm:items-start">
                  <time className="font-mono text-xs text-slate-400">{formatTime(event.time)}</time>
                  <span className={"text-xs font-semibold " + (info?.color ?? "text-slate-300")}>{info?.label ?? "System"}</span>
                  <div>
                    <p className="text-xs leading-5 text-slate-200">{event.message}</p>
                    {event.details.scenario_id ? (
                      <p className="mt-1 font-mono text-[11px] text-slate-400">scenario_id: {String(event.details.scenario_id)}</p>
                    ) : null}
                  </div>
                </article>
              );
            })}
          </div>
        </section>
        <p className="text-xs leading-5 text-slate-400">
          Phiên demo này mới xác minh được contract Start → Stream → Stop → Report.
          Bước tích hợp tiếp theo là kết nối Zeek Collector, adapter phát hiện AI theo schema phù hợp,
          và trình thực thi kiểm thử được giới hạn trong mạng Host-only.
        </p>
      </div>
    </AppShell>
  );
}
