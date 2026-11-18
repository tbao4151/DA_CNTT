"use client";

import React, { useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { EmptyState, KpiCard, Panel } from "@/components/ui";
import type { DatasetEvaluationResponse } from "@/lib/types";
import { formatNumber, formatPercent } from "@/lib/utils";

export function EvaluationTab({ data }: { data: DatasetEvaluationResponse }) {
  const [showAllFeatures, setShowAllFeatures] = useState(false);
  const bm = data.benchmark_metrics;
  const cmp = data.locked_threshold_comparison;
  const fi = data.feature_importance;
  const diag = data.sample_threshold_diagnostics;

  const cmTotal = bm
    ? bm.confusion_matrix.tn +
      bm.confusion_matrix.fp +
      bm.confusion_matrix.fn +
      bm.confusion_matrix.tp
    : 0;

  return (
    <div className="space-y-4">
      {/* Official Benchmark & Confusion Matrix */}
      <Panel>
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Benchmark chính thức (Official Held-Out Test)
            </h2>
            <p className="text-xs text-slate-400">
              {bm
                ? `Nguồn: ${bm.source_file} (${bm.source_kind === "local_artifacts" ? "Artifact cục bộ" : "Báo cáo official lưu trữ trong repo"}). KHÔNG phải kết quả của vài dòng CSV đang xem.`
                : "Chưa có tệp số liệu đánh giá."}
            </p>
          </div>
          {bm && (
            <span className="rounded border border-slate-700 bg-subtle px-2.5 py-1 font-mono text-[11px] text-slate-300">
              Train {formatNumber(bm.train_size)} · Test {formatNumber(bm.test_size)}
            </span>
          )}
        </div>

        {bm ? (
          <div className="space-y-4">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <KpiCard label="Attack Precision" value={formatPercent(bm.attack_precision)} accent="blue" />
              <KpiCard label="Attack Recall" value={formatPercent(bm.attack_recall)} accent="teal" />
              <KpiCard label="Attack F1" value={formatPercent(bm.attack_f1)} accent="default" />
              <KpiCard
                label="Average Precision"
                value={bm.average_precision_attack.toFixed(4)}
                accent="default"
              />
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
              <div className="lg:col-span-7 overflow-x-auto">
                <table className="w-full min-w-[420px] border-collapse text-center text-xs tabular-nums">
                  <thead>
                    <tr className="border-b border-slate-800 bg-subtle text-slate-300">
                      <th className="border border-slate-800 p-2.5 text-left">Thực tế \ Dự đoán</th>
                      <th className="border border-slate-800 p-2.5">Dự đoán Normal (0)</th>
                      <th className="border border-slate-800 p-2.5">Dự đoán Attack (1)</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <th className="border border-slate-800 bg-subtle p-2.5 text-left text-slate-300">
                        Thực tế Normal (0)
                      </th>
                      <td className="border border-slate-800 bg-emerald-950/30 p-3 text-emerald-200">
                        <div className="font-mono text-lg font-bold">
                          {formatNumber(bm.confusion_matrix.tn)}
                        </div>
                        <div className="text-[11px] opacity-80">
                          TN ·{" "}
                          {(
                            (bm.confusion_matrix.tn /
                              Math.max(1, bm.confusion_matrix.tn + bm.confusion_matrix.fp)) *
                            100
                          ).toFixed(1)}
                          % Normal đúng
                        </div>
                      </td>
                      <td className="border border-slate-800 bg-orange-950/35 p-3 text-orange-200">
                        <div className="font-mono text-lg font-bold">
                          {formatNumber(bm.confusion_matrix.fp)}
                        </div>
                        <div className="text-[11px] opacity-85">
                          FP (Báo nhầm) ·{" "}
                          {(
                            (bm.confusion_matrix.fp /
                              Math.max(1, bm.confusion_matrix.tn + bm.confusion_matrix.fp)) *
                            100
                          ).toFixed(1)}
                          % FPR
                        </div>
                      </td>
                    </tr>
                    <tr>
                      <th className="border border-slate-800 bg-subtle p-2.5 text-left text-slate-300">
                        Thực tế Attack (1)
                      </th>
                      <td className="border border-slate-800 bg-red-950/40 p-3 text-red-200">
                        <div className="font-mono text-lg font-bold">
                          {formatNumber(bm.confusion_matrix.fn)}
                        </div>
                        <div className="text-[11px] opacity-85">
                          FN (Bỏ sót) ·{" "}
                          {(
                            (bm.confusion_matrix.fn /
                              Math.max(1, bm.confusion_matrix.fn + bm.confusion_matrix.tp)) *
                            100
                          ).toFixed(1)}
                          % FNR
                        </div>
                      </td>
                      <td className="border border-slate-800 bg-emerald-950/30 p-3 text-emerald-200">
                        <div className="font-mono text-lg font-bold">
                          {formatNumber(bm.confusion_matrix.tp)}
                        </div>
                        <div className="text-[11px] opacity-80">
                          TP ·{" "}
                          {(
                            (bm.confusion_matrix.tp /
                              Math.max(1, bm.confusion_matrix.fn + bm.confusion_matrix.tp)) *
                            100
                          ).toFixed(1)}
                          % Recall
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
              <div className="lg:col-span-5 space-y-2.5 rounded-xl border border-slate-800 bg-subtle p-4 text-xs leading-relaxed text-slate-300">
                <div className="font-semibold text-slate-100">
                  Ý nghĩa vận hành SOC (Ngưỡng 0,50 trên {formatNumber(cmTotal)} flows)
                </div>
                <p>
                  <strong className="text-orange-300">False Positive ({formatNumber(bm.confusion_matrix.fp)}):</strong>{" "}
                  Số flow bình thường bị mô hình gắn cờ Attack — tạo gánh nặng sàng lọc thủ công cho chuyên viên SOC.
                </p>
                <p>
                  <strong className="text-red-300">False Negative ({formatNumber(bm.confusion_matrix.fn)}):</strong>{" "}
                  Số flow tấn công thực tế bị bỏ sót ở ngưỡng mặc định 0,50.
                </p>
                <p className="text-slate-400">
                  Các nhãn ground truth (<code className="font-mono text-slate-300">id</code>,{" "}
                  <code className="font-mono text-slate-300">label</code>,{" "}
                  <code className="font-mono text-slate-300">attack_cat</code>) luôn bị loại bỏ hoàn toàn trước khi đưa vào Random Forest.
                </p>
              </div>
            </div>
          </div>
        ) : (
          <EmptyState
            title="Chưa có dữ liệu benchmark"
            description="Không tìm thấy metrics.json hoặc reports/official_baseline_metrics.json."
          />
        )}
      </Panel>

      {/* Locked threshold comparison */}
      {cmp && !cmp.error && cmp.baseline && cmp.candidate && (
        <Panel>
          <div className="mb-3">
            <h3 className="text-sm font-semibold text-slate-100">
              So sánh ngưỡng đã khóa · Official UNSW-NB15 Test (0,50 vs 0,55)
            </h3>
            <p className="text-xs text-slate-400">
              Đọc từ <code className="font-mono text-slate-300">reports/official_locked_threshold_comparison.json</code> ({formatNumber(cmp.test_rows)} flows · Validation run #{cmp.validation_selection_run_id} · Test run #{cmp.evaluation_run_id}).
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[600px] border-collapse text-left text-xs tabular-nums">
              <thead>
                <tr className="border-b border-slate-800 bg-subtle text-[11px] uppercase text-slate-400">
                  <th className="px-3 py-2">Ngưỡng</th>
                  <th className="px-3 py-2">TP</th>
                  <th className="px-3 py-2">FP</th>
                  <th className="px-3 py-2">TN</th>
                  <th className="px-3 py-2">FN</th>
                  <th className="px-3 py-2">Precision</th>
                  <th className="px-3 py-2">Recall</th>
                  <th className="px-3 py-2">F1</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 font-mono">
                {[
                  { name: "Baseline 0,50", row: cmp.baseline },
                  { name: "Validation-locked 0,55", row: cmp.candidate },
                ].map((item) => (
                  <tr key={item.name}>
                    <td className="px-3 py-2 font-sans font-semibold text-slate-100">{item.name}</td>
                    <td className="px-3 py-2 text-slate-200">{formatNumber(item.row.true_positive)}</td>
                    <td className="px-3 py-2 text-orange-300">{formatNumber(item.row.false_positive)}</td>
                    <td className="px-3 py-2 text-slate-200">{formatNumber(item.row.true_negative)}</td>
                    <td className="px-3 py-2 text-red-300">{formatNumber(item.row.false_negative)}</td>
                    <td className="px-3 py-2 text-slate-100">{formatPercent(item.row.precision_attack, 2)}</td>
                    <td className="px-3 py-2 text-slate-100">{formatPercent(item.row.recall_attack, 2)}</td>
                    <td className="px-3 py-2 text-slate-100">{formatPercent(item.row.f1_attack, 2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-3 flex flex-wrap gap-4 font-mono text-xs">
            <span className="text-emerald-300">
              Thay đổi FP: {cmp.delta_false_positive_candidate_minus_baseline}
            </span>
            <span className="text-amber-300">
              Thay đổi FN: +{cmp.delta_false_negative_candidate_minus_baseline}
            </span>
            <span className="font-sans text-slate-400">
              (Đánh đổi thực nghiệm; ngưỡng Alert Queue không tự động thay đổi.)
            </span>
          </div>
        </Panel>
      )}

      {/* Global Feature Importance + Threshold Diagnostics */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel className="min-w-0">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                AI Explainability · Global Feature Importance (Top 12)
              </h3>
              <p className="text-xs text-slate-400">{fi ? fi.note : "Chưa có dữ liệu MDI."}</p>
            </div>
            {fi && (
              <button
                type="button"
                onClick={() => setShowAllFeatures((v) => !v)}
                className="rounded border border-slate-700 bg-subtle px-2.5 py-1 text-[11px] text-slate-300 hover:bg-slate-800"
              >
                {showAllFeatures ? "Thu gọn" : `Xem cả ${fi.features.length} đặc trưng`}
              </button>
            )}
          </div>
          {fi && fi.features.length > 0 ? (
            <>
              <div className="h-72 w-full min-w-0">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={fi.features.slice(0, 12).reverse()}
                    layout="vertical"
                    margin={{ top: 4, right: 16, left: 30, bottom: 4 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                    <XAxis type="number" stroke="#94a3b8" fontSize={11} unit="%" />
                    <YAxis type="category" dataKey="feature" stroke="#cbd5e1" fontSize={11} width={96} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#0f172a",
                        borderColor: "#334155",
                        borderRadius: "8px",
                        fontSize: "12px",
                        color: "#f8fafc",
                      }}
                    />
                    <Bar dataKey="importance_percent" name="MDI (%)" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              {showAllFeatures && (
                <div className="mt-3 max-h-64 overflow-y-auto rounded-lg border border-slate-800">
                  <table className="w-full border-collapse text-left text-xs tabular-nums">
                    <thead className="sticky top-0 bg-subtle text-[11px] text-slate-400">
                      <tr>
                        <th className="px-3 py-1.5">#</th>
                        <th className="px-3 py-1.5">Đặc trưng</th>
                        <th className="px-3 py-1.5">MDI (%)</th>
                        <th className="px-3 py-1.5">Số chiều mã hóa</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 font-mono">
                      {fi.features.map((f) => (
                        <tr key={f.feature}>
                          <td className="px-3 py-1.5 text-slate-400">{f.rank}</td>
                          <td className="px-3 py-1.5 text-slate-100">{f.feature}</td>
                          <td className="px-3 py-1.5 text-sky-300">{f.importance_percent.toFixed(2)}%</td>
                          <td className="px-3 py-1.5 text-slate-300">{f.encoded_dimensions}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          ) : (
            <EmptyState
              title="Chưa có dữ liệu Feature Importance"
              description="Cần mô hình cục bộ hoặc báo cáo official_global_feature_importance.json."
            />
          )}
        </Panel>

        <Panel className="min-w-0">
          <div className="mb-3">
            <h3 className="text-sm font-semibold text-slate-100">
              Chẩn đoán ngưỡng trên mẫu đang xem
            </h3>
            <p className="text-xs text-slate-400">{diag.message}</p>
          </div>
          {diag.status === "ok" && diag.rows.length > 0 ? (
            <div className="space-y-3">
              <div className="h-56 w-full min-w-0">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={diag.rows} margin={{ top: 6, right: 14, left: 0, bottom: 4 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="threshold" stroke="#94a3b8" fontSize={11} />
                    <YAxis stroke="#94a3b8" fontSize={11} domain={[0, 1]} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#0f172a",
                        borderColor: "#334155",
                        borderRadius: "8px",
                        fontSize: "12px",
                        color: "#f8fafc",
                      }}
                    />
                    <Legend wrapperStyle={{ fontSize: "11px" }} />
                    <Line type="monotone" dataKey="precision_attack" name="Precision" stroke="#3b82f6" strokeWidth={2} />
                    <Line type="monotone" dataKey="recall_attack" name="Recall" stroke="#14b8a6" strokeWidth={2} />
                    <Line type="monotone" dataKey="false_positive_rate" name="FPR" stroke="#f59e0b" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
              <div className="overflow-x-auto rounded-lg border border-slate-800">
                <table className="w-full border-collapse text-left text-xs font-mono tabular-nums">
                  <thead className="bg-subtle text-[11px] text-slate-400">
                    <tr>
                      <th className="px-2.5 py-1.5">Ngưỡng</th>
                      <th className="px-2.5 py-1.5">TP</th>
                      <th className="px-2.5 py-1.5">FP</th>
                      <th className="px-2.5 py-1.5">Precision</th>
                      <th className="px-2.5 py-1.5">Recall</th>
                      <th className="px-2.5 py-1.5">Cảnh báo</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {diag.rows.map((r) => (
                      <tr key={r.threshold}>
                        <td className="px-2.5 py-1.5 text-slate-100">{r.threshold.toFixed(2)}</td>
                        <td className="px-2.5 py-1.5 text-slate-200">{formatNumber(r.true_positive)}</td>
                        <td className="px-2.5 py-1.5 text-orange-300">{formatNumber(r.false_positive)}</td>
                        <td className="px-2.5 py-1.5 text-slate-200">{formatPercent(r.precision_attack)}</td>
                        <td className="px-2.5 py-1.5 text-slate-200">{formatPercent(r.recall_attack)}</td>
                        <td className="px-2.5 py-1.5 text-sky-300">{formatNumber(r.alerts)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : diag.status === "counts_only" ? (
            <div className="overflow-x-auto rounded-lg border border-slate-800">
              <table className="w-full border-collapse text-left text-xs font-mono tabular-nums">
                <thead className="bg-subtle text-[11px] text-slate-400">
                  <tr>
                    <th className="px-3 py-2">Ngưỡng xác suất</th>
                    <th className="px-3 py-2">Số cảnh báo trên mẫu</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {diag.rows.map((r) => (
                    <tr key={r.threshold}>
                      <td className="px-3 py-2 text-slate-100">{r.threshold.toFixed(2)}</td>
                      <td className="px-3 py-2 text-sky-300">{formatNumber(r.alerts)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title="Chưa thể chạy chẩn đoán ngưỡng"
              description={diag.message ?? "Cần mô hình AI cục bộ để tính xác suất dự đoán."}
            />
          )}
        </Panel>
      </div>
    </div>
  );
}
