"use client";

import React, { useState } from "react";
import { Download, FolderPlus, Save } from "lucide-react";
import {
  EmptyState,
  ErrorBanner,
  KpiCard,
  LoadingRows,
  Panel,
  PriorityBadge,
  SuccessBanner,
} from "@/components/ui";
import type {
  DatasetAlertsResponse,
  FlowRow,
  SocCaseDetailResponse,
  SocCaseSummary,
} from "@/lib/types";
import { formatNumber, formatPercent, formatUtcDateTime } from "@/lib/utils";

export function AlertsTab({
  data,
  loading,
  threshold,
  priority,
  onChangeThreshold,
  onChangePriority,
  onCreateCase,
  onInspectRow,
}: {
  data: DatasetAlertsResponse | null;
  loading: boolean;
  threshold: number;
  priority: string;
  onChangeThreshold: (value: number) => void;
  onChangePriority: (value: string) => void;
  onCreateCase: (row: FlowRow) => Promise<void>;
  onInspectRow: (row: FlowRow) => void;
}) {
  const [selectedRow, setSelectedRow] = useState<FlowRow | null>(null);
  const [creating, setCreating] = useState(false);

  const activeSelection =
    selectedRow && data?.alerts.some((a) => a.flow_ref === selectedRow.flow_ref)
      ? selectedRow
      : data?.alerts[0] ?? null;

  return (
    <div className="space-y-4">
      <Panel>
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="max-w-xl space-y-1">
            <h2 className="text-sm font-semibold text-slate-100">
              Trung tâm cảnh báo · Hàng đợi flow AI nghi vấn
            </h2>
            <p className="text-xs text-slate-400">
              Điều chỉnh ngưỡng xác suất Attack (mặc định 0,80). Tăng ngưỡng giúp giảm cảnh báo nhầm nhưng có thể bỏ sót tấn công.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-4">
            <div className="space-y-1">
              <div className="flex items-center justify-between gap-4 text-xs">
                <label htmlFor="alert-threshold" className="text-slate-300">
                  Ngưỡng P(Attack):
                </label>
                <span className="font-mono font-bold text-sky-300 tabular-nums">
                  {threshold.toFixed(2)}
                </span>
              </div>
              <input
                id="alert-threshold"
                type="range"
                min={0.5}
                max={0.99}
                step={0.01}
                value={threshold}
                onChange={(e) => onChangeThreshold(Number(e.target.value))}
                className="w-52 accent-blue-500"
              />
            </div>
            <KpiCard
              label="Cảnh báo ở ngưỡng"
              value={data ? formatNumber(data.total_alerts) : "—"}
              accent="amber"
            />
          </div>
        </div>
      </Panel>

      {loading && !data ? (
        <LoadingRows count={5} />
      ) : data && !data.predictions_available ? (
        <EmptyState
          title="Chưa thể tạo cảnh báo AI"
          description={data.message ?? "Chưa có mô hình Random Forest cục bộ."}
          hint="Chạy `python scripts/train_siem.py` trên máy để huấn luyện và nạp mô hình."
        />
      ) : data && data.total_alerts === 0 ? (
        <EmptyState
          title="Không có cảnh báo vượt ngưỡng đã chọn"
          description={`Ở ngưỡng P(Attack) >= ${threshold.toFixed(2)}, không có flow nào bị gắn cờ trong mẫu đang tải. Điều này KHÔNG đồng nghĩa không có tấn công ở dưới ngưỡng.`}
          hint="Hãy hạ thanh trượt ngưỡng hoặc kiểm tra sang tab Threat hunting."
        />
      ) : data ? (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <Panel className="xl:col-span-7">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap gap-1.5">
                {[
                  { key: "ALL", label: `Tất cả (${formatNumber(data.total_alerts)})` },
                  { key: "CRIT", label: `[CRIT] ${formatNumber(data.priority_counts.CRIT)}` },
                  { key: "HIGH", label: `[HIGH] ${formatNumber(data.priority_counts.HIGH)}` },
                  { key: "MED", label: `[MED] ${formatNumber(data.priority_counts.MED)}` },
                  { key: "LOW", label: `[LOW] ${formatNumber(data.priority_counts.LOW)}` },
                ].map((pill) => (
                  <button
                    key={pill.key}
                    type="button"
                    onClick={() => onChangePriority(pill.key)}
                    className={`rounded-md border px-2.5 py-1 font-mono text-[11px] font-semibold ${
                      priority === pill.key
                        ? "border-blue-500/50 bg-blue-600/25 text-blue-200"
                        : "border-slate-700 bg-subtle text-slate-300 hover:bg-slate-800"
                    }`}
                  >
                    {pill.label}
                  </button>
                ))}
              </div>
              <span className="text-[11px] text-slate-400">Tối đa 300 flow điểm cao nhất</span>
            </div>

            <div className="max-h-[460px] overflow-auto rounded-lg border border-slate-800">
              <table className="w-full min-w-[540px] border-collapse text-left text-xs">
                <thead className="sticky top-0 bg-subtle text-[11px] uppercase text-slate-400">
                  <tr>
                    <th className="px-3 py-2">Flow Ref</th>
                    <th className="px-3 py-2">Proto / Service</th>
                    <th className="px-3 py-2">P(Attack)</th>
                    <th className="px-3 py-2">Ưu tiên</th>
                    <th className="px-3 py-2">Bytes (Src/Dst)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {data.alerts.map((row) => {
                    const isSel = activeSelection?.flow_ref === row.flow_ref;
                    return (
                      <tr
                        key={`${row.row_index}-${row.flow_ref}`}
                        onClick={() => setSelectedRow(row)}
                        className={`cursor-pointer transition-colors ${
                          isSel ? "bg-blue-950/50" : "hover:bg-slate-800/50"
                        }`}
                      >
                        <td className="px-3 py-2 font-mono font-semibold text-sky-300">
                          {row.flow_ref}
                        </td>
                        <td className="px-3 py-2 font-mono text-slate-200">
                          {row.proto ?? "—"} / {row.service ?? "—"}
                        </td>
                        <td className="px-3 py-2 font-mono font-bold tabular-nums text-slate-100">
                          {formatPercent(row.AI_attack_probability, 1)}
                        </td>
                        <td className="px-3 py-2">
                          <PriorityBadge
                            code={row.priority_band.code}
                            label={row.priority_band.label}
                          />
                        </td>
                        <td className="px-3 py-2 font-mono tabular-nums text-slate-300">
                          {formatNumber(row.sbytes)} / {formatNumber(row.dbytes)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Panel>

          {/* Selected alert triage panel */}
          <Panel className="xl:col-span-5">
            {activeSelection ? (
              <div className="space-y-4">
                <div className="flex flex-wrap items-start justify-between gap-2 border-b border-slate-800 pb-3">
                  <div>
                    <div className="font-mono text-xs text-slate-400">
                      Bản ghi #{activeSelection.row_index + 1}
                    </div>
                    <h3 className="font-mono text-base font-bold text-slate-100">
                      Flow {activeSelection.flow_ref}
                    </h3>
                  </div>
                  <PriorityBadge
                    code={activeSelection.priority_band.code}
                    label={activeSelection.priority_band.label}
                  />
                </div>

                <div className="grid grid-cols-2 gap-2.5 font-mono text-xs">
                  <div className="rounded-lg border border-slate-800 bg-canvas p-2.5">
                    <div className="text-[10px] text-slate-500">AI P(Attack)</div>
                    <div className="mt-0.5 text-base font-bold text-amber-300 tabular-nums">
                      {formatPercent(activeSelection.AI_attack_probability, 2)}
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-canvas p-2.5">
                    <div className="text-[10px] text-slate-500">PROTO / STATE</div>
                    <div className="mt-0.5 font-semibold text-slate-200">
                      {activeSelection.proto ?? "—"} · {activeSelection.state ?? "—"}
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-canvas p-2.5">
                    <div className="text-[10px] text-slate-500">SRC / DST BYTES</div>
                    <div className="mt-0.5 font-semibold text-slate-200 tabular-nums">
                      {formatNumber(activeSelection.sbytes)} / {formatNumber(activeSelection.dbytes)}
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-canvas p-2.5">
                    <div className="text-[10px] text-slate-500">FLOW RATE</div>
                    <div className="mt-0.5 font-semibold text-slate-200 tabular-nums">
                      {activeSelection.rate !== null ? activeSelection.rate.toFixed(1) : "—"}
                    </div>
                  </div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-subtle p-3 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">
                      Tín hiệu quy tắc phụ trợ (không phải kết luận)
                    </span>
                    <span className="font-mono text-amber-300">
                      {activeSelection.signal_score}/100
                    </span>
                  </div>
                  <p className="mt-1 text-slate-400">
                    {activeSelection.signal_reasons.length > 0
                      ? activeSelection.signal_reasons.join("; ")
                      : "Không kích hoạt quy tắc mẫu bổ sung."}
                  </p>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => onInspectRow(activeSelection)}
                    className="rounded-lg border border-slate-700 px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800"
                  >
                    Xem toàn bộ đặc trưng
                  </button>
                  <button
                    type="button"
                    disabled={creating}
                    onClick={async () => {
                      setCreating(true);
                      try {
                        await onCreateCase(activeSelection);
                      } finally {
                        setCreating(false);
                      }
                    }}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
                  >
                    <FolderPlus className="h-3.5 w-3.5" />
                    {creating ? "Đang tạo hồ sơ..." : "Tạo SOC case từ flow đã chọn"}
                  </button>
                </div>
              </div>
            ) : null}
          </Panel>
        </div>
      ) : null}
    </div>
  );
}

export function CasesTab({
  cases,
  caseStates,
  stateFilter,
  selectedCaseId,
  caseDetail,
  loadingDetail,
  onChangeStateFilter,
  onSelectCase,
  onUpdateCase,
  onExportCase,
}: {
  cases: SocCaseSummary[];
  caseStates: string[];
  stateFilter: string;
  selectedCaseId: number | null;
  caseDetail: SocCaseDetailResponse | null;
  loadingDetail: boolean;
  onChangeStateFilter: (state: string) => void;
  onSelectCase: (caseId: number) => void;
  onUpdateCase: (caseId: number, state: string, note: string) => Promise<void>;
  onExportCase: (caseId: number) => void;
}) {
  const [editState, setEditState] = useState<string>("Investigating");
  const [editNote, setEditNote] = useState<string>("");
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [showFullJson, setShowFullJson] = useState(false);

  const detailCaseId = caseDetail?.case.case_id ?? null;

  React.useEffect(() => {
    if (caseDetail) {
      setEditState(caseDetail.case.state);
      setEditNote(caseDetail.case.analyst_note || "");
    }
  }, [caseDetail]);

  React.useEffect(() => {
    setMsg(null);
    setErr(null);
  }, [detailCaseId]);

  return (
    <div className="space-y-4">
      <Panel>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              SOC Case Management · Hồ sơ &amp; Lịch sử điều tra
            </h2>
            <p className="text-xs text-slate-400">
              Mỗi case lưu bản chụp flow bất biến và lịch sử cập nhật trong SQLite cục bộ (<code className="font-mono text-slate-300">runtime/soc_cases.sqlite3</code>).
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {["ALL", ...caseStates].map((st) => (
              <button
                key={st}
                type="button"
                onClick={() => onChangeStateFilter(st)}
                className={`rounded-md border px-2.5 py-1 font-mono text-[11px] ${
                  stateFilter === st
                    ? "border-blue-500/50 bg-blue-600/25 text-blue-200"
                    : "border-slate-700 bg-subtle text-slate-300 hover:bg-slate-800"
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </Panel>

      {cases.length === 0 ? (
        <EmptyState
          title="Chưa có hồ sơ SOC phù hợp"
          description="Không tìm thấy hồ sơ nào trong phạm vi trạng thái đã chọn."
          hint="Tạo case mới từ tab Trung tâm cảnh báo hoặc chuyển bộ lọc trạng thái về ALL."
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          {/* Case list */}
          <Panel className="xl:col-span-5">
            <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
              Danh sách hồ sơ ({cases.length})
            </div>
            <div className="max-h-[540px] space-y-2 overflow-y-auto pr-1">
              {cases.map((c) => {
                const active = selectedCaseId === c.case_id;
                return (
                  <button
                    key={c.case_id}
                    type="button"
                    onClick={() => onSelectCase(c.case_id)}
                    className={`w-full rounded-xl border p-3 text-left transition-colors ${
                      active
                        ? "border-blue-500/60 bg-blue-950/40"
                        : "border-slate-800 bg-canvas/70 hover:bg-slate-800/50"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs font-bold text-sky-300">
                        Case #{c.case_id} · {c.flow_id}
                      </span>
                      <span className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 font-mono text-[10px] text-slate-200">
                        {c.state}
                      </span>
                    </div>
                    <div className="mt-1.5 flex items-center justify-between font-mono text-[11px] text-slate-400">
                      <span>
                        {c.verdict} ({formatPercent(c.confidence)})
                      </span>
                      <span>{formatUtcDateTime(c.updated_at)}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          </Panel>

          {/* Master-Detail case inspector & update */}
          <Panel className="xl:col-span-7">
            {loadingDetail ? (
              <LoadingRows count={5} />
            ) : caseDetail ? (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                  <div>
                    <h3 className="font-mono text-base font-bold text-slate-100">
                      Case #{caseDetail.case.case_id} · Flow {caseDetail.case.flow_id}
                    </h3>
                    <div className="mt-0.5 font-mono text-xs text-slate-400">
                      Verdict: {caseDetail.case.verdict} · Confidence:{" "}
                      {formatPercent(caseDetail.case.confidence, 2)} · Tạo:{" "}
                      {formatUtcDateTime(caseDetail.case.created_at)}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => onExportCase(caseDetail.case.case_id)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-subtle px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Xuất JSON hồ sơ
                  </button>
                </div>

                {/* Key snapshot fields */}
                <div>
                  <div className="mb-2 flex items-center justify-between">
                    <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                      Bằng chứng lưu khi mở hồ sơ (Snapshot)
                    </span>
                    <button
                      type="button"
                      onClick={() => setShowFullJson((v) => !v)}
                      className="text-xs text-sky-400 hover:text-sky-300"
                    >
                      {showFullJson ? "Ẩn JSON đầy đủ" : "Xem JSON đầy đủ"}
                    </button>
                  </div>
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                    {["proto", "service", "state", "dur", "sbytes", "dbytes", "rate", "ct_srv_src"]
                      .filter((k) => k in caseDetail.flow_evidence)
                      .map((k) => (
                        <div
                          key={k}
                          className="rounded-lg border border-slate-800 bg-canvas px-2.5 py-2"
                        >
                          <div className="font-mono text-[10px] uppercase text-slate-500">{k}</div>
                          <div className="mt-0.5 truncate font-mono text-xs font-semibold text-slate-200">
                            {String(caseDetail.flow_evidence[k])}
                          </div>
                        </div>
                      ))}
                  </div>
                  {showFullJson && (
                    <pre className="mt-2 max-h-56 overflow-auto rounded-lg border border-slate-800 bg-canvas p-3 font-mono text-[11px] text-slate-300">
                      {JSON.stringify(caseDetail.flow_evidence, null, 2)}
                    </pre>
                  )}
                </div>

                {/* Audit history */}
                <div>
                  <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Lịch sử điều tra (Audit Trail)
                  </div>
                  <div className="max-h-48 overflow-auto rounded-lg border border-slate-800">
                    <table className="w-full border-collapse text-left text-xs">
                      <thead className="bg-subtle text-[11px] text-slate-400">
                        <tr>
                          <th className="px-3 py-1.5">Thời gian UTC</th>
                          <th className="px-3 py-1.5">Chuyển trạng thái</th>
                          <th className="px-3 py-1.5">Ghi chú</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                        {caseDetail.case_events.map((ev) => (
                          <tr key={ev.event_id}>
                            <td className="px-3 py-1.5 font-mono text-[11px] text-slate-400">
                              {formatUtcDateTime(ev.created_at)}
                            </td>
                            <td className="px-3 py-1.5 font-mono text-slate-200">
                              {ev.old_state ? `${ev.old_state} → ` : ""}
                              <span className="text-sky-300">{ev.new_state}</span>
                            </td>
                            <td className="px-3 py-1.5 text-slate-300">{ev.note}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Update form */}
                <form
                  onSubmit={async (e) => {
                    e.preventDefault();
                    setSaving(true);
                    setMsg(null);
                    setErr(null);
                    try {
                      await onUpdateCase(caseDetail.case.case_id, editState, editNote);
                      setMsg("Đã lưu diễn biến điều tra.");
                    } catch (error) {
                      setErr(error instanceof Error ? error.message : "Không thể cập nhật case");
                    } finally {
                      setSaving(false);
                    }
                  }}
                  className="space-y-3 rounded-xl border border-slate-800 bg-subtle p-4"
                >
                  <div className="text-xs font-semibold text-slate-200">Cập nhật diễn biến xử lý</div>
                  {msg && <SuccessBanner message={msg} />}
                  {err && <ErrorBanner message={err} />}
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                    <div>
                      <label className="mb-1 block text-xs text-slate-300" htmlFor="case-state-select">
                        Trạng thái xử lý
                      </label>
                      <select
                        id="case-state-select"
                        value={editState}
                        onChange={(e) => setEditState(e.target.value)}
                        className="w-full rounded-lg border border-slate-700 bg-canvas px-2.5 py-2 text-xs text-slate-100"
                      >
                        {caseDetail.case_states.map((st) => (
                          <option key={st} value={st}>
                            {st}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div className="sm:col-span-2">
                      <label className="mb-1 block text-xs text-slate-300" htmlFor="case-note-input">
                        Ghi chú điều tra (bắt buộc)
                      </label>
                      <textarea
                        id="case-note-input"
                        rows={2}
                        maxLength={2000}
                        required
                        value={editNote}
                        onChange={(e) => setEditNote(e.target.value)}
                        placeholder="Ghi lại bằng chứng, nhận định và hướng xử lý..."
                        className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 text-xs text-slate-100 placeholder:text-slate-500"
                      />
                    </div>
                  </div>
                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={saving}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
                    >
                      <Save className="h-3.5 w-3.5" />
                      {saving ? "Đang lưu..." : "Lưu diễn biến điều tra"}
                    </button>
                  </div>
                </form>
              </div>
            ) : (
              <EmptyState
                title="Chọn một hồ sơ để kiểm tra"
                description="Nhấp vào một hồ sơ bên trái để xem bằng chứng flow snapshot, audit trail và cập nhật trạng thái."
              />
            )}
          </Panel>
        </div>
      )}
    </div>
  );
}
