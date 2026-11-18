"use client";

import React from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ArrowUpRight } from "lucide-react";
import { EmptyState, KpiCard, Panel, PriorityBadge } from "@/components/ui";
import type { DatasetOverviewResponse } from "@/lib/types";
import { formatNumber, formatPercent, formatUtcDateTime } from "@/lib/utils";

export function OverviewTab({
  data,
  onSelectTab,
}: {
  data: DatasetOverviewResponse;
  onSelectTab: (tab: "hunting" | "evaluation" | "alerts" | "cases", caseId?: number) => void;
}) {
  const { provenance, kpis, priority_distribution, protocol_distribution, attack_category_distribution, recent_cases } =
    data;

  return (
    <div className="space-y-4">
      {/* Provenance Strip */}
      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-lg border border-slate-800 bg-surface px-3.5 py-2.5">
          <div className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
            Nguồn dữ liệu đang tải
          </div>
          <div className="mt-0.5 truncate font-mono text-xs font-semibold text-slate-100">
            {provenance.source_display}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-surface px-3.5 py-2.5">
          <div className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
            Phạm vi mẫu (Offline)
          </div>
          <div className="mt-0.5 font-mono text-xs font-semibold text-slate-100 tabular-nums">
            {formatNumber(provenance.rows_loaded)} dòng đầu (limit {formatNumber(provenance.sample_size_limit)})
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-surface px-3.5 py-2.5">
          <div className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
            Trạng thái AI Model
          </div>
          <div className="mt-0.5 font-mono text-xs font-semibold">
            {provenance.predictions_available ? (
              <span className="text-emerald-300">Random Forest cục bộ · Sẵn sàng</span>
            ) : (
              <span className="text-amber-300">Chế độ khám phá (Chưa có model)</span>
            )}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-surface px-3.5 py-2.5">
          <div className="font-mono text-[10px] uppercase tracking-wider text-slate-400">
            Giám sát trực tiếp / IP gốc
          </div>
          <div className="mt-0.5 font-mono text-xs font-semibold text-slate-300">
            TẮT · Dữ liệu lịch sử (Không có IP/Timestamp)
          </div>
        </div>
      </div>

      {/* 4 KPIs */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          label="Flows đã đọc"
          value={formatNumber(kpis.flows_read)}
          sublabel="Số bản ghi trong mẫu hiện tại"
          accent="blue"
        />
        <KpiCard
          label="Attack trong nhãn gốc"
          value={
            kpis.ground_truth_attacks !== null
              ? formatNumber(kpis.ground_truth_attacks)
              : "Không có nhãn"
          }
          sublabel="Ground truth (không đưa vào AI)"
          accent="teal"
        />
        <KpiCard
          label="AI dự đoán Attack"
          value={
            kpis.ai_predicted_attacks !== null
              ? formatNumber(kpis.ai_predicted_attacks)
              : "Chưa huấn luyện"
          }
          sublabel={
            provenance.predictions_available
              ? "Dự đoán ở ngưỡng mặc định 0,50"
              : "Cần artifacts/unsw_binary_rf.joblib"
          }
          accent={provenance.predictions_available ? "amber" : "default"}
        />
        <KpiCard
          label="Hồ sơ SOC"
          value={formatNumber(kpis.soc_cases_total)}
          sublabel="Lưu trong runtime/soc_cases.sqlite3"
          accent="default"
        />
      </div>

      {/* Priority distribution */}
      {priority_distribution ? (
        <Panel>
          <div className="flex flex-col justify-between gap-2 border-b border-slate-800 pb-3 sm:flex-row sm:items-center">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">
                Phân tầng ưu tiên điều tra theo xác suất mô hình AI (Mẫu đang xem)
              </h2>
              <p className="text-xs text-slate-400">
                Chỉ dùng sắp xếp thứ tự điều tra theo P(Attack); không đồng nghĩa mức độ sự cố mạng thực tế.
              </p>
            </div>
            <button
              type="button"
              onClick={() => onSelectTab("alerts")}
              className="inline-flex w-fit items-center gap-1 rounded-lg border border-blue-500/40 bg-blue-950/50 px-3 py-1.5 text-xs font-medium text-blue-200 hover:bg-blue-900/60"
            >
              Mở Trung tâm cảnh báo
              <ArrowUpRight className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="mt-3 flex flex-wrap gap-2.5">
            <PriorityBadge code="CRIT" label={`[CRIT] >= 0.90: ${formatNumber(priority_distribution.critical)}`} />
            <PriorityBadge code="HIGH" label={`[HIGH] 0.80–0.89: ${formatNumber(priority_distribution.high)}`} />
            <PriorityBadge code="MED" label={`[MED] 0.65–0.79: ${formatNumber(priority_distribution.medium)}`} />
            <PriorityBadge code="LOW" label={`[LOW] 0.50–0.64: ${formatNumber(priority_distribution.low)}`} />
            <PriorityBadge code="INFO" label={`[INFO] Normal < 0.50: ${formatNumber(priority_distribution.normal)}`} />
          </div>
        </Panel>
      ) : null}

      {/* Charts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel className="min-w-0">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">Phân bố giao thức (Top 10)</h3>
              <p className="text-xs text-slate-400">
                Số lượng network flow theo trường <code className="font-mono text-slate-300">proto</code>
              </p>
            </div>
          </div>
          <div className="h-64 w-full min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={protocol_distribution} margin={{ top: 8, right: 12, left: 0, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis
                  dataKey="name"
                  stroke="#94a3b8"
                  fontSize={11}
                  tickLine={false}
                  interval={0}
                  angle={-18}
                  textAnchor="end"
                  height={44}
                />
                <YAxis stroke="#94a3b8" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderColor: "#334155",
                    borderRadius: "8px",
                    fontSize: "12px",
                    color: "#f8fafc",
                  }}
                />
                <Bar dataKey="count" name="Số flow" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel className="min-w-0">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Loại tấn công được gán nhãn (Ground Truth)
              </h3>
              <p className="text-xs text-slate-400">Nhãn có sẵn trong dataset để đối chiếu, không phải dự đoán AI</p>
            </div>
          </div>
          {attack_category_distribution && attack_category_distribution.length > 0 ? (
            <div className="h-64 w-full min-w-0">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={attack_category_distribution} margin={{ top: 8, right: 12, left: 0, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis
                    dataKey="name"
                    stroke="#94a3b8"
                    fontSize={11}
                    tickLine={false}
                    interval={0}
                    angle={-18}
                    textAnchor="end"
                    height={44}
                  />
                  <YAxis stroke="#94a3b8" fontSize={11} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#334155",
                      borderRadius: "8px",
                      fontSize: "12px",
                      color: "#f8fafc",
                    }}
                  />
                  <Bar dataKey="count" name="Số flow" fill="#14b8a6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState
              title="Không có cột nhãn tấn công (attack_cat)"
              description="Tệp CSV đang tải không chứa cột nhãn ground truth. Hệ thống vẫn hiển thị đặc trưng lưu lượng và dự đoán AI (nếu có mô hình)."
            />
          )}
        </Panel>
      </div>

      {/* Recent SOC cases */}
      <Panel>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">Hoạt động hồ sơ SOC gần nhất</h3>
            <p className="text-xs text-slate-400">
              Các hồ sơ điều tra được lập từ luồng Dataset Mode trong SQLite cục bộ
            </p>
          </div>
          <button
            type="button"
            onClick={() => onSelectTab("cases")}
            className="text-xs font-medium text-sky-400 hover:text-sky-300"
          >
            Xem tất cả hồ sơ &rarr;
          </button>
        </div>
        {recent_cases.length === 0 ? (
          <EmptyState
            title="Chưa có hồ sơ SOC nào được tạo"
            description="Cơ sở dữ liệu SQLite cục bộ chưa ghi nhận hồ sơ điều tra nào."
            hint="Vào Trung tâm cảnh báo hoặc Threat hunting để chọn flow nghi vấn và tạo case đầu tiên."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[600px] border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] uppercase tracking-wider text-slate-400">
                  <th className="py-2 pr-3">Case</th>
                  <th className="py-2 pr-3">Flow Ref</th>
                  <th className="py-2 pr-3">Verdict</th>
                  <th className="py-2 pr-3">Confidence</th>
                  <th className="py-2 pr-3">Trạng thái</th>
                  <th className="py-2">Cập nhật (UTC)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {recent_cases.map((c) => (
                  <tr
                    key={c.case_id}
                    onClick={() => onSelectTab("cases", c.case_id)}
                    className="cursor-pointer hover:bg-slate-800/40"
                  >
                    <td className="py-2 pr-3 font-mono font-semibold text-sky-300">#{c.case_id}</td>
                    <td className="py-2 pr-3 font-mono text-slate-200">{c.flow_id}</td>
                    <td className="py-2 pr-3 font-mono text-slate-200">{c.verdict}</td>
                    <td className="py-2 pr-3 font-mono tabular-nums text-slate-300">
                      {formatPercent(c.confidence)}
                    </td>
                    <td className="py-2 pr-3">
                      <span className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-slate-200">
                        {c.state}
                      </span>
                    </td>
                    <td className="py-2 font-mono text-[11px] text-slate-400">
                      {formatUtcDateTime(c.updated_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
