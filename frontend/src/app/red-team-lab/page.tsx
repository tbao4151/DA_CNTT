"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Download, Play, RotateCcw, Send } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import {
  EmptyState,
  ErrorBanner,
  KpiCard,
  LoadingRows,
  ModeBanner,
  Panel,
  PriorityBadge,
  SuccessBanner,
} from "@/components/ui";
import { api } from "@/lib/api";
import type { RedTeamBenchmarkResponse, RedTeamStateResponse } from "@/lib/types";
import { downloadBlob, formatNumber } from "@/lib/utils";

export default function RedTeamLabPage() {
  const [state, setState] = useState<RedTeamStateResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const [strategy, setStrategy] = useState<"ucb1" | "random">("ucb1");
  const [seed, setSeed] = useState<number>(42);

  const [blueFlagged, setBlueFlagged] = useState<boolean>(true);
  const [confirmFeedback, setConfirmFeedback] = useState<boolean>(false);

  const [simRounds, setSimRounds] = useState<number>(120);
  const [simTrials, setSimTrials] = useState<number>(12);
  const [simSeed, setSimSeed] = useState<number>(42);
  const [benchmark, setBenchmark] = useState<RedTeamBenchmarkResponse | null>(null);
  const [runningSim, setRunningSim] = useState(false);

  const loadState = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.getRedTeamState("default");
      setState(res);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể tải trạng thái Red Team Lab");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadState();
  }, [loadState]);

  const benchmarkChartData = benchmark
    ? Object.entries(benchmark.policies).map(([name, details]) => ({
        strategy: name.toUpperCase(),
        unflagged: Number(details.mean_synthetic_unflagged_fraction.toFixed(4)),
        regret: Number(details.mean_expected_pseudo_regret.toFixed(4)),
      }))
    : [];

  return (
    <AppShell
      title="Red Team Lab · Scenario Planner"
      breadcrumb="Red Team / Simulation Planner"
      provenanceTag="EXECUTION OFF · OFFLINE PLANNER"
    >
      <ModeBanner
        variant="red"
        tag="EXECUTION OFF · NON-EXECUTING"
        title="Môi trường lập kế hoạch kịch bản mô phỏng — Không phát lưu lượng mạng thật"
        description="Trang này CHỈ chọn nhãn kịch bản trong danh mục cố định và chạy thí nghiệm Bernoulli tổng hợp (UCB1 vs Random). Không điều khiển VMware, không quét/khai thác, không tự động đánh giá Blue Team."
      />

      {error && <ErrorBanner message={error} onRetry={() => void loadState()} />}
      {success && <SuccessBanner message={success} />}

      {loading && !state ? (
        <LoadingRows count={5} />
      ) : state ? (
        <>
          {/* KPIs */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <KpiCard
              label="Kịch bản offline"
              value={formatNumber(state.scenarios.length)}
              sublabel="Danh mục cố định không payload"
              accent="red"
            />
            <KpiCard
              label="Phản hồi thủ công"
              value={formatNumber(state.summary.total)}
              sublabel="Chưa xác minh bằng log SOC"
              accent="amber"
            />
            <KpiCard
              label="Kết nối mạng"
              value="TẮT (DISABLED)"
              sublabel="execution_enabled = false"
              accent="red"
            />
            <KpiCard
              label="Đề xuất đang chờ"
              value={
                state.audit.pending_proposal_id !== null
                  ? `#${state.audit.pending_proposal_id}`
                  : "Không có"
              }
              sublabel={`Giới hạn phiên: ${state.audit.proposals}/${state.max_proposals}`}
              accent="default"
            />
          </div>

          {/* Scenario Catalog */}
          <Panel>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-semibold text-slate-100">
                  1. Danh mục kiểm thử được định nghĩa sẵn
                </h2>
                <p className="text-xs text-slate-400">
                  Chỉ chứa mô tả mục tiêu phân tích; không chứa IP, lệnh shell, payload hoặc tệp thực thi.
                </p>
              </div>
              <PriorityBadge code="RED" label="[EXECUTION OFF]" />
            </div>
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full min-w-[540px] border-collapse text-left text-xs">
                <thead className="bg-subtle text-[11px] uppercase text-slate-400">
                  <tr>
                    <th className="px-3 py-2">Scenario ID</th>
                    <th className="px-3 py-2">Kịch bản</th>
                    <th className="px-3 py-2">Loại</th>
                    <th className="px-3 py-2">Mục tiêu phân tích</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {state.scenarios.map((s) => (
                    <tr key={s.scenario_id}>
                      <td className="px-3 py-2 font-mono font-semibold text-red-300">
                        {s.scenario_id}
                      </td>
                      <td className="px-3 py-2 font-medium text-slate-100">{s.title}</td>
                      <td className="px-3 py-2 font-mono text-slate-400">{s.category}</td>
                      <td className="px-3 py-2 text-slate-300">{s.objective}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Panel>

          {/* Planner + Feedback */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Panel className="space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  2. Tác nhân lựa chọn kịch bản (UCB1 vs Seeded Random)
                </h3>
                <p className="text-xs text-slate-400">
                  Phải hoàn tất phản hồi cho đề xuất đang chờ trước khi tạo đề xuất mới.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-4 text-xs">
                <label className="flex cursor-pointer items-center gap-2 text-slate-200">
                  <input
                    type="radio"
                    name="rt-strategy"
                    checked={strategy === "ucb1"}
                    onChange={() => setStrategy("ucb1")}
                  />
                  UCB1 (Exploration / Exploitation)
                </label>
                <label className="flex cursor-pointer items-center gap-2 text-slate-200">
                  <input
                    type="radio"
                    name="rt-strategy"
                    checked={strategy === "random"}
                    onChange={() => setStrategy("random")}
                  />
                  Random baseline
                </label>
                <label className="flex items-center gap-2 text-slate-300">
                  Seed:
                  <input
                    type="number"
                    min={0}
                    max={1000000}
                    disabled={strategy !== "random"}
                    value={seed}
                    onChange={(e) => setSeed(Number(e.target.value))}
                    className="w-24 rounded border border-slate-700 bg-canvas px-2 py-1 font-mono text-xs text-slate-100 disabled:opacity-40"
                  />
                </label>
              </div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  disabled={
                    state.audit.pending_proposal_id !== null ||
                    state.audit.proposals >= state.max_proposals
                  }
                  onClick={async () => {
                    setError(null);
                    setSuccess(null);
                    try {
                      const next = await api.proposeRedTeamScenario({ strategy, seed });
                      setState(next);
                      setSuccess(
                        `Đã tạo đề xuất kịch bản: ${next.pending_plan?.scenario_id ?? ""} (EXECUTION OFF).`
                      );
                    } catch (err) {
                      setError(err instanceof Error ? err.message : "Không thể đề xuất kịch bản");
                    }
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-xs font-semibold text-white hover:bg-red-500 disabled:opacity-40"
                >
                  <Play className="h-3.5 w-3.5" />
                  Đề xuất kịch bản (không thực thi)
                </button>
                <button
                  type="button"
                  onClick={async () => {
                    const next = await api.resetRedTeamSession("default");
                    setState(next);
                    setSuccess("Đã dừng phiên lập kế hoạch và xóa lịch sử phản hồi trong phiên.");
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-subtle px-3 py-2 text-xs text-slate-300 hover:bg-slate-800"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  Dừng phiên &amp; xóa phản hồi
                </button>
              </div>

              {state.pending_plan ? (
                <div className="space-y-2 rounded-xl border border-red-500/30 bg-red-950/25 p-3.5 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-slate-100">
                      Đề xuất đang chờ: {state.pending_plan.title} (
                      <code className="font-mono text-red-300">{state.pending_plan.scenario_id}</code>)
                    </span>
                    <button
                      type="button"
                      onClick={() => {
                        const blob = new Blob([JSON.stringify(state.pending_plan, null, 2)], {
                          type: "application/json",
                        });
                        downloadBlob(blob, "red_team_offline_plan.json");
                      }}
                      className="inline-flex items-center gap-1 rounded border border-slate-700 bg-canvas px-2 py-1 font-mono text-[11px] text-slate-200 hover:bg-slate-800"
                    >
                      <Download className="h-3 w-3" />
                      JSON
                    </button>
                  </div>
                  <p className="text-slate-300">{state.pending_plan.rationale}</p>
                </div>
              ) : null}
            </Panel>

            <Panel className="space-y-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  3. Phản hồi quan sát thủ công (Chưa kiểm chứng)
                </h3>
                <p className="text-xs text-slate-400">
                  Chỉ minh họa cách UCB1 cập nhật lựa chọn; không phải dữ liệu đo lường Blue Team thật.
                </p>
              </div>
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (state.audit.pending_proposal_id === null) return;
                  setError(null);
                  try {
                    const next = await api.submitRedTeamFeedback({
                      proposal_id: state.audit.pending_proposal_id,
                      blue_flagged: blueFlagged,
                      confirm: confirmFeedback,
                    });
                    setState(next);
                    setConfirmFeedback(false);
                    setSuccess("Đã ghi nhận phản hồi thủ công vào timeline phiên.");
                  } catch (err) {
                    setError(err instanceof Error ? err.message : "Không thể gửi phản hồi");
                  }
                }}
                className="space-y-3 text-xs"
              >
                <div className="rounded-lg border border-slate-800 bg-canvas px-3 py-2 font-mono text-slate-300">
                  Đề xuất đang chờ:{" "}
                  {state.pending_plan
                    ? `#${state.audit.pending_proposal_id} · ${state.pending_plan.scenario_id}`
                    : "Chưa có đề xuất đang chờ phản hồi"}
                </div>
                <div className="flex gap-4">
                  <label className="flex cursor-pointer items-center gap-2 text-slate-200">
                    <input
                      type="radio"
                      name="blue-flagged"
                      checked={blueFlagged === true}
                      onChange={() => setBlueFlagged(true)}
                      disabled={!state.pending_plan}
                    />
                    Blue Team đánh dấu (Flagged)
                  </label>
                  <label className="flex cursor-pointer items-center gap-2 text-slate-200">
                    <input
                      type="radio"
                      name="blue-flagged"
                      checked={blueFlagged === false}
                      onChange={() => setBlueFlagged(false)}
                      disabled={!state.pending_plan}
                    />
                    Không đánh dấu (Unflagged)
                  </label>
                </div>
                <label className="flex cursor-pointer items-start gap-2 text-slate-300">
                  <input
                    type="checkbox"
                    checked={confirmFeedback}
                    onChange={(e) => setConfirmFeedback(e.target.checked)}
                    disabled={!state.pending_plan}
                    className="mt-0.5"
                  />
                  Tôi xác nhận đây là phản hồi thủ công chưa được kiểm chứng bằng log SOC.
                </label>
                <button
                  type="submit"
                  disabled={!state.pending_plan || !confirmFeedback}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white hover:bg-blue-500 disabled:opacity-40"
                >
                  <Send className="h-3.5 w-3.5" />
                  Thêm phản hồi
                </button>
              </form>
            </Panel>
          </div>

          {/* Audit Timeline */}
          <Panel>
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  4. Timeline đề xuất và phản hồi ngoại tuyến
                </h3>
                <p className="text-xs text-slate-400">
                  Lưu trong bộ nhớ phiên, không có chữ ký số và không chứa lưu lượng mạng thật.
                </p>
              </div>
              {state.audit.events.length > 0 && (
                <button
                  type="button"
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(state.audit, null, 2)], {
                      type: "application/json",
                    });
                    downloadBlob(blob, "red_team_offline_planning_audit.json");
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-subtle px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
                >
                  <Download className="h-3.5 w-3.5" />
                  Xuất timeline JSON
                </button>
              )}
            </div>
            {state.audit.events.length === 0 ? (
              <EmptyState
                title="Chưa có sự kiện nào trong phiên lập kế hoạch"
                description="Nhấn 'Đề xuất kịch bản (không thực thi)' ở mục 2 để bắt đầu chuỗi đề xuất & phản hồi."
              />
            ) : (
              <div className="max-h-60 overflow-auto rounded-lg border border-slate-800">
                <table className="w-full border-collapse text-left text-xs font-mono">
                  <thead className="bg-subtle text-[11px] text-slate-400">
                    <tr>
                      <th className="px-3 py-2">Seq</th>
                      <th className="px-3 py-2">Loại</th>
                      <th className="px-3 py-2">Proposal ID</th>
                      <th className="px-3 py-2">Scenario</th>
                      <th className="px-3 py-2">Chi tiết</th>
                      <th className="px-3 py-2">UTC</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {state.audit.events.map((ev) => (
                      <tr key={String(ev.sequence)}>
                        <td className="px-3 py-1.5 text-slate-400">{String(ev.sequence)}</td>
                        <td className="px-3 py-1.5 text-slate-200">{String(ev.kind)}</td>
                        <td className="px-3 py-1.5 text-slate-300">#{String(ev.proposal_id)}</td>
                        <td className="px-3 py-1.5 text-red-300">{String(ev.scenario_id)}</td>
                        <td className="px-3 py-1.5 text-slate-300">
                          {ev.kind === "proposal"
                            ? `strategy=${String(ev.strategy)}, exec=${String(ev.execution_enabled)}`
                            : `blue_flagged=${String(ev.blue_flagged)}, verified=${String(ev.verified)}`}
                        </td>
                        <td className="px-3 py-1.5 text-[11px] text-slate-400">
                          {String(ev.recorded_at_utc)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          {/* Synthetic Benchmark */}
          <Panel className="space-y-4">
            <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  5. So sánh UCB1 và Random trên dữ liệu TỔNG HỢP (Synthetic Bernoulli Simulation)
                </h3>
                <p className="text-xs text-amber-300/90">
                  Thí nghiệm mô phỏng Bernoulli với xác suất giả định trước — KHÔNG phải kết quả tấn công hay tỷ lệ phát hiện AI thật.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <label className="flex items-center gap-1 text-slate-300">
                  Rounds:
                  <input
                    type="number"
                    min={3}
                    max={500}
                    value={simRounds}
                    onChange={(e) => setSimRounds(Number(e.target.value))}
                    className="w-16 rounded border border-slate-700 bg-canvas px-2 py-1 font-mono text-slate-100"
                  />
                </label>
                <label className="flex items-center gap-1 text-slate-300">
                  Trials:
                  <input
                    type="number"
                    min={2}
                    max={40}
                    value={simTrials}
                    onChange={(e) => setSimTrials(Number(e.target.value))}
                    className="w-16 rounded border border-slate-700 bg-canvas px-2 py-1 font-mono text-slate-100"
                  />
                </label>
                <label className="flex items-center gap-1 text-slate-300">
                  Seed:
                  <input
                    type="number"
                    min={0}
                    max={1000000}
                    value={simSeed}
                    onChange={(e) => setSimSeed(Number(e.target.value))}
                    className="w-20 rounded border border-slate-700 bg-canvas px-2 py-1 font-mono text-slate-100"
                  />
                </label>
                <button
                  type="button"
                  disabled={runningSim}
                  onClick={async () => {
                    setRunningSim(true);
                    setError(null);
                    try {
                      const res = await api.runRedTeamSyntheticBenchmark({
                        rounds: simRounds,
                        trials: simTrials,
                        seed: simSeed,
                      });
                      setBenchmark(res);
                    } catch (err) {
                      setError(err instanceof Error ? err.message : "Lỗi chạy mô phỏng tổng hợp");
                    } finally {
                      setRunningSim(false);
                    }
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-3.5 py-1.5 font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5" />
                  {runningSim ? "Đang mô phỏng..." : "Chạy so sánh mô phỏng"}
                </button>
              </div>
            </div>

            {benchmark && (
              <div className="space-y-4">
                <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                  <div className="h-56 w-full min-w-0">
                    <div className="mb-1 text-xs font-medium text-slate-300">
                      Tỷ lệ unflagged mô phỏng trung bình (SYNTHETIC)
                    </div>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={benchmarkChartData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                        <XAxis dataKey="strategy" stroke="#94a3b8" fontSize={11} />
                        <YAxis stroke="#94a3b8" fontSize={11} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#0f172a",
                            borderColor: "#334155",
                            borderRadius: "8px",
                            fontSize: "12px",
                            color: "#f8fafc",
                          }}
                        />
                        <Bar dataKey="unflagged" name="Unflagged (Synthetic)" fill="#ef4444" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="h-56 w-full min-w-0">
                    <div className="mb-1 text-xs font-medium text-slate-300">
                      Expected pseudo-regret trung bình (thấp hơn = tốt hơn)
                    </div>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={benchmarkChartData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                        <XAxis dataKey="strategy" stroke="#94a3b8" fontSize={11} />
                        <YAxis stroke="#94a3b8" fontSize={11} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#0f172a",
                            borderColor: "#334155",
                            borderRadius: "8px",
                            fontSize: "12px",
                            color: "#f8fafc",
                          }}
                        />
                        <Bar dataKey="regret" name="Pseudo-regret" fill="#14b8a6" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <p className="text-xs text-slate-400">{benchmark.interpretation_warning}</p>
              </div>
            )}
          </Panel>
        </>
      ) : null}
    </AppShell>
  );
}
