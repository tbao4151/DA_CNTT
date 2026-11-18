"use client";

import React, { useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Check, Copy, Download, FileCode, FolderPlus, Search, Upload } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import {
  FlowInspectorDrawer,
  type InspectorPayload,
} from "@/components/FlowInspectorDrawer";
import {
  EmptyState,
  ErrorBanner,
  KpiCard,
  ModeBanner,
  Panel,
  PriorityBadge,
  SuccessBanner,
} from "@/components/ui";
import { api } from "@/lib/api";
import type {
  CyberLabParseResponse,
  CyberLabTraceResponse,
  ZeekEventRow,
} from "@/lib/types";
import { downloadBlob, formatNumber } from "@/lib/utils";

export default function CyberLabPage() {
  const [parsed, setParsed] = useState<CyberLabParseResponse | null>(null);
  const [trace, setTrace] = useState<CyberLabTraceResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);

  const [protoFilter, setProtoFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");

  const [selectedRecordIndex, setSelectedRecordIndex] = useState<number>(0);
  const [manualConsent, setManualConsent] = useState(false);
  const [lastExport, setLastExport] = useState<Record<string, unknown> | null>(null);
  const [lastCaseId, setLastCaseId] = useState<number | null>(null);

  const [selectedCandidateIndex, setSelectedCandidateIndex] = useState<number>(0);
  const [researchConsent, setResearchConsent] = useState(false);

  const [inspector, setInspector] = useState<InspectorPayload | null>(null);

  const handleLogUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    setError(null);
    setSuccess(null);
    setTrace(null);
    setLastExport(null);
    try {
      const res = await api.parseZeekLog(file);
      setParsed(res);
      setSelectedRecordIndex(0);
      setSuccess(`Đã xác thực cấu trúc Zeek ASCII (${res.filename}). Dữ liệu ngoại tuyến, chưa chạy AI.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể đọc Zeek conn.log");
    } finally {
      setLoading(false);
      e.target.value = "";
    }
  };

  const handleLoadSample = async () => {
    setLoading(true);
    setError(null);
    setSuccess(null);
    setTrace(null);
    setLastExport(null);
    try {
      const res = await api.loadSampleZeekFixture();
      setParsed(res);
      setSelectedRecordIndex(0);
      setSuccess("Đã nạp mẫu Zeek conn.log tổng hợp (synthetic fixture) để kiểm thử giao diện ngoại tuyến.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể nạp mẫu Zeek");
    } finally {
      setLoading(false);
    }
  };

  const handleTraceUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !parsed) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.reviewZeekTrace(parsed.summary.source_sha256, file);
      setTrace(res);
      if (res.candidates.length > 0) {
        setSelectedCandidateIndex(res.candidates[0].record_index);
      }
      setSuccess("Đã đối chiếu SHA-256 và toàn bộ UID giữa conn.log và trace nghiên cứu held-out.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Không thể đối chiếu trace JSON");
    } finally {
      setLoading(false);
      e.target.value = "";
    }
  };

  const filteredEvents = useMemo(() => {
    if (!parsed) return [];
    const q = searchQuery.trim().toLowerCase();
    return parsed.events.filter((ev) => {
      if (protoFilter && ev.proto !== protoFilter) return false;
      if (
        q &&
        !ev.uid.toLowerCase().includes(q) &&
        !ev.src_ip.toLowerCase().includes(q) &&
        !ev.dst_ip.toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });
  }, [parsed, protoFilter, searchQuery]);

  const protocolChartData = useMemo(() => {
    if (!parsed) return [];
    return Object.entries(parsed.summary.protocol_counts).map(([name, count]) => ({
      name,
      count,
    }));
  }, [parsed]);

  const openZeekInspector = (ev: ZeekEventRow) => {
    setInspector({
      title: `Zeek Flow ${ev.uid}`,
      subtitle: `Dòng #${ev.row_number} · ${ev.src_ip}:${ev.src_port} → ${ev.dst_ip}:${ev.dst_port}`,
      badgeCode: "BLUE",
      badgeLabel: ev.proto.toUpperCase(),
      evidence: ev as unknown as Record<string, unknown>,
    });
  };

  return (
    <AppShell
      title="Cyber Lab · Blue Team Zeek Telemetry"
      breadcrumb="Blue Team / Cyber Lab"
      provenanceTag={
        parsed?.is_synthetic_demo
          ? "SYNTHETIC FIXTURE · OFFLINE TEST"
          : "OFFLINE ZEEK CONN.LOG"
      }
    >
      <ModeBanner
        variant="blue"
        tag="BLUE TEAM · OFFLINE ZEEK"
        title="Trình khám phá Zeek conn.log ngoại tuyến (Môi trường VMware: Chưa kiểm tra kết nối trực tiếp)"
        description="Không bắt gói tin trực tiếp, không tự động suy luận AI hay phát cảnh báo khi upload. Dữ liệu IP/timestamp chỉ phản ánh nội dung tệp ngoại tuyến."
      />

      {error && <ErrorBanner message={error} onRetry={() => setError(null)} />}
      {success && <SuccessBanner message={success} />}

      {/* Ingestion bar */}
      <Panel>
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Nạp tệp Zeek ASCII <code className="font-mono text-teal-300">conn.log</code> (tối đa 15 MiB · 10.000 flows)
            </h2>
            <p className="text-xs text-slate-400">
              Xác thực định dạng TSV Zeek, kiểm tra dấu vết SHA-256 và đối chiếu trace nghiên cứu tùy chọn.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg bg-teal-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-teal-500">
              <Upload className="h-3.5 w-3.5" />
              {loading ? "Đang phân tích..." : "Chọn tệp conn.log"}
              <input
                type="file"
                accept=".log,.tsv,.txt"
                disabled={loading}
                onChange={handleLogUpload}
                className="sr-only"
              />
            </label>
            <button
              type="button"
              disabled={loading}
              onClick={() => void handleLoadSample()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-subtle px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800"
            >
              <FileCode className="h-3.5 w-3.5 text-teal-400" />
              Nạp mẫu tổng hợp để kiểm thử UI
            </button>
          </div>
        </div>
      </Panel>

      {!parsed ? (
        <EmptyState
          title="Chưa có dữ liệu Cyber Lab"
          description="Hệ thống không tự giả lập lưu lượng mạng thật. Vui lòng nạp tệp conn.log của lab hoặc bấm 'Nạp mẫu tổng hợp để kiểm thử UI' để xem đầy đủ quy trình."
          hint="Quy trình: (1) Nạp conn.log → (2) Kiểm tra SHA-256 & bảng flow → (3) Mở hồ sơ thủ công Unclassified."
        />
      ) : (
        <>
          {parsed.is_synthetic_demo && (
            <div className="rounded-xl border border-amber-500/40 bg-amber-950/35 px-4 py-2.5 text-xs text-amber-200">
              <strong>[SYNTHETIC DEMO DATA]</strong> Đang hiển thị tệp <code className="font-mono">synthetic_demo_conn.log</code> tổng hợp phục vụ kiểm thử giao diện — không phải dữ liệu thu thập từ VMware thật.
            </div>
          )}

          {/* KPIs + SHA-256 */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <KpiCard
              label="Flow hợp lệ"
              value={formatNumber(parsed.summary.flow_count)}
              sublabel={`Tệp: ${parsed.filename}`}
              accent="teal"
            />
            <KpiCard
              label="IP nguồn duy nhất"
              value={formatNumber(parsed.summary.unique_sources)}
              sublabel="Theo id.orig_h"
              accent="blue"
            />
            <KpiCard
              label="IP đích duy nhất"
              value={formatNumber(parsed.summary.unique_destinations)}
              sublabel="Theo id.resp_h"
              accent="default"
            />
          </div>

          <Panel>
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="min-w-0">
                <div className="font-mono text-[11px] uppercase tracking-wider text-slate-400">
                  Source SHA-256 · Khung thời gian Zeek (UTC): {parsed.summary.first_event_utc} &rarr;{" "}
                  {parsed.summary.last_event_utc}
                </div>
                <div className="mt-1 break-all font-mono text-xs text-teal-300">
                  {parsed.summary.source_sha256}
                </div>
              </div>
              <button
                type="button"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(parsed.summary.source_sha256);
                    setCopiedHash(true);
                    setTimeout(() => setCopiedHash(false), 1800);
                  } catch {
                    // ignore clipboard failure
                  }
                }}
                className="inline-flex w-fit shrink-0 items-center gap-1.5 rounded-lg border border-slate-700 bg-subtle px-3 py-1.5 font-mono text-xs text-slate-200 hover:bg-slate-800"
              >
                {copiedHash ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                {copiedHash ? "Đã chép SHA-256" : "Chép SHA-256"}
              </button>
            </div>
          </Panel>

          {/* Chart + Preview table */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
            <Panel className="min-w-0 lg:col-span-4">
              <h3 className="mb-2 text-sm font-semibold text-slate-100">Phân bố giao thức</h3>
              <div className="h-64 w-full min-w-0">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={protocolChartData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                    <XAxis dataKey="name" stroke="#94a3b8" fontSize={11} />
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
                    <Bar dataKey="count" name="Số flow" fill="#14b8a6" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Panel>

            <Panel className="lg:col-span-8">
              <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-100">
                    Bản ghi Zeek (tối đa 500 dòng đầu)
                  </h3>
                  <p className="text-xs text-slate-400">
                    Nhấp vào dòng để xem toàn bộ thông số trong ngăn chi tiết.
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <select
                    aria-label="Lọc giao thức Zeek"
                    value={protoFilter}
                    onChange={(e) => setProtoFilter(e.target.value)}
                    className="rounded-lg border border-slate-700 bg-canvas px-2.5 py-1.5 text-xs text-slate-100"
                  >
                    <option value="">Tất cả proto</option>
                    {Object.keys(parsed.summary.protocol_counts).map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                  <div className="relative">
                    <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-500" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Tìm UID / IP..."
                      className="rounded-lg border border-slate-700 bg-canvas py-1.5 pl-8 pr-3 text-xs text-slate-100 placeholder:text-slate-500"
                    />
                  </div>
                </div>
              </div>

              <div className="max-h-72 overflow-auto rounded-lg border border-slate-800">
                <table className="w-full min-w-[680px] border-collapse text-left text-xs">
                  <thead className="sticky top-0 bg-subtle text-[11px] uppercase text-slate-400">
                    <tr>
                      <th className="px-3 py-2">#</th>
                      <th className="px-3 py-2">UID</th>
                      <th className="px-3 py-2">Src &rarr; Dst</th>
                      <th className="px-3 py-2">Proto/Svc</th>
                      <th className="px-3 py-2">Bytes (O/R)</th>
                      <th className="px-3 py-2">UTC</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 font-mono">
                    {filteredEvents.map((ev) => (
                      <tr
                        key={ev.uid}
                        onClick={() => openZeekInspector(ev)}
                        className="cursor-pointer hover:bg-slate-800/50"
                      >
                        <td className="px-3 py-1.5 text-slate-400">{ev.row_number}</td>
                        <td className="px-3 py-1.5 text-teal-300">{ev.uid}</td>
                        <td className="px-3 py-1.5 text-slate-200">
                          {ev.src_ip}:{ev.src_port} &rarr; {ev.dst_ip}:{ev.dst_port}
                        </td>
                        <td className="px-3 py-1.5 text-slate-300">
                          {ev.proto}/{ev.service ?? "-"}
                        </td>
                        <td className="px-3 py-1.5 text-slate-300 tabular-nums">
                          {ev.orig_bytes ?? "-"}/{ev.resp_bytes ?? "-"}
                        </td>
                        <td className="px-3 py-1.5 text-[11px] text-slate-400">
                          {ev.event_time_utc}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          </div>

          {/* Trace Review + Manual Unclassified Triage */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Panel className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-semibold text-slate-100">
                    Đối chiếu dự đoán AI nghiên cứu (Chỉ đọc)
                  </h3>
                  <p className="text-xs text-slate-400">
                    Tùy chọn nạp JSON private <code className="font-mono text-slate-300">--trace-output</code> để kiểm tra SHA-256 và ứng viên Attack.
                  </p>
                </div>
                <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-slate-700 bg-subtle px-3 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800">
                  <Upload className="h-3.5 w-3.5" />
                  Nạp Trace JSON
                  <input
                    type="file"
                    accept=".json,application/json"
                    onChange={handleTraceUpload}
                    className="sr-only"
                  />
                </label>
              </div>
              {trace ? (
                <div className="space-y-3">
                  <div className="flex flex-wrap gap-3 font-mono text-xs">
                    <span className="text-teal-300">Khớp nguồn: {trace.flow_count}</span>
                    <span className="text-amber-300">Ứng viên Attack: {trace.candidate_count}</span>
                    <span className="text-slate-400">Ngưỡng: {trace.selected_threshold.toFixed(2)}</span>
                  </div>
                  {trace.candidates.length > 0 ? (
                    <>
                      <div className="max-h-48 overflow-auto rounded-lg border border-slate-800">
                        <table className="w-full border-collapse text-left text-xs font-mono">
                          <thead className="bg-subtle text-[11px] text-slate-400">
                            <tr>
                              <th className="px-2.5 py-1.5">Dòng</th>
                              <th className="px-2.5 py-1.5">UID</th>
                              <th className="px-2.5 py-1.5">P(Attack)</th>
                              <th className="px-2.5 py-1.5">Ưu tiên</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800">
                            {trace.candidates.map((c) => (
                              <tr key={c.uid}>
                                <td className="px-2.5 py-1.5 text-slate-300">{c.zeek_row}</td>
                                <td className="px-2.5 py-1.5 text-teal-300">{c.uid}</td>
                                <td className="px-2.5 py-1.5 text-slate-100">
                                  {(c.attack_probability * 100).toFixed(1)}%
                                </td>
                                <td className="px-2.5 py-1.5">
                                  <PriorityBadge code={c.priority_band.code} label={c.priority_band.label} />
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                      <div className="space-y-2 rounded-lg border border-slate-800 bg-subtle p-3 text-xs">
                        <select
                          aria-label="Ứng viên nghiên cứu cần điều tra"
                          value={selectedCandidateIndex}
                          onChange={(e) => setSelectedCandidateIndex(Number(e.target.value))}
                          className="w-full rounded border border-slate-700 bg-canvas px-2.5 py-1.5 font-mono text-xs text-slate-100"
                        >
                          {trace.candidates
                            .filter((c) => c.selectable_for_case)
                            .map((c) => (
                              <option key={c.uid} value={c.record_index}>
                                Dòng {c.zeek_row} · {c.uid} · P={(c.attack_probability * 100).toFixed(1)}%
                              </option>
                            ))}
                        </select>
                        <label className="flex cursor-pointer items-start gap-2 text-slate-300">
                          <input
                            type="checkbox"
                            checked={researchConsent}
                            onChange={(e) => setResearchConsent(e.target.checked)}
                            className="mt-0.5"
                          />
                          Tôi đã xem bằng chứng và chủ động mở hồ sơ nghiên cứu Unclassified; không coi đây là tấn công đã xác nhận.
                        </label>
                        <button
                          type="button"
                          disabled={!researchConsent}
                          onClick={async () => {
                            setError(null);
                            try {
                              const res = await api.createCyberLabResearchCase({
                                source_sha256: parsed.summary.source_sha256,
                                trace_sha256: trace.trace_sha256,
                                record_index: selectedCandidateIndex,
                                analyst_confirmed: researchConsent,
                              });
                              setLastCaseId(res.case_id);
                              setLastExport(res.verified_export);
                              setSuccess(`Đã mở hồ sơ nghiên cứu #${res.case_id} (Unclassified).`);
                            } catch (err) {
                              setError(err instanceof Error ? err.message : "Lỗi tạo hồ sơ");
                            }
                          }}
                          className="inline-flex items-center gap-1.5 rounded-lg bg-teal-600 px-3.5 py-2 font-semibold text-white hover:bg-teal-500 disabled:opacity-40"
                        >
                          <FolderPlus className="h-3.5 w-3.5" />
                          Mở hồ sơ nghiên cứu Unclassified
                        </button>
                      </div>
                    </>
                  ) : (
                    <p className="text-xs text-slate-400">Không có ứng viên Attack vượt ngưỡng trong trace.</p>
                  )}
                </div>
              ) : (
                <p className="text-xs text-slate-400">
                  Chưa nạp trace JSON. Chức năng này là tùy chọn, dành cho bài đánh giá held-out Zeek riêng tư.
                </p>
              )}
            </Panel>

            <Panel className="space-y-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  Tạo hồ sơ điều tra thủ công (Unclassified)
                </h3>
                <p className="text-xs text-slate-400">
                  Lưu vào <code className="font-mono text-slate-300">runtime/cyber_lab_cases.sqlite3</code>. Yêu cầu xác nhận quyền xử lý hợp lệ; không tự động tạo khi upload.
                </p>
              </div>
              <select
                aria-label="Chọn dòng Zeek để lập hồ sơ"
                value={selectedRecordIndex}
                onChange={(e) => setSelectedRecordIndex(Number(e.target.value))}
                className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-xs text-slate-100"
              >
                {parsed.events.map((ev) => (
                  <option key={ev.uid} value={ev.record_index}>
                    Dòng {ev.row_number} · {ev.uid} · {ev.src_ip} → {ev.dst_ip} ({ev.proto})
                  </option>
                ))}
              </select>
              <label className="flex cursor-pointer items-start gap-2 text-xs text-slate-300">
                <input
                  type="checkbox"
                  checked={manualConsent}
                  onChange={(e) => setManualConsent(e.target.checked)}
                  className="mt-0.5"
                />
                Tôi xác nhận đây là log được phép xử lý và muốn tạo hồ sơ điều tra thủ công (Unclassified).
              </label>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={!manualConsent}
                  onClick={async () => {
                    setError(null);
                    try {
                      const res = await api.createCyberLabManualCase({
                        source_sha256: parsed.summary.source_sha256,
                        record_index: selectedRecordIndex,
                        consent: manualConsent,
                      });
                      setLastCaseId(res.case_id);
                      setLastExport(res.verified_export);
                      setSuccess(`Đã tạo hồ sơ thủ công #${res.case_id} (Unclassified).`);
                    } catch (err) {
                      setError(err instanceof Error ? err.message : "Không thể tạo hồ sơ");
                    }
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-40"
                >
                  <FolderPlus className="h-3.5 w-3.5" />
                  Tạo hồ sơ Unclassified
                </button>
                {lastExport && lastCaseId !== null && (
                  <button
                    type="button"
                    onClick={() => {
                      const blob = new Blob([JSON.stringify(lastExport, null, 2)], {
                        type: "application/json",
                      });
                      downloadBlob(blob, `cyber_lab_case_${lastCaseId}.json`);
                    }}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-subtle px-3 py-2 text-xs font-medium text-slate-200 hover:bg-slate-800"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Tải JSON đối chiếu log gốc (#{lastCaseId})
                  </button>
                )}
              </div>
            </Panel>
          </div>
        </>
      )}

      <FlowInspectorDrawer payload={inspector} onClose={() => setInspector(null)} />
    </AppShell>
  );
}
