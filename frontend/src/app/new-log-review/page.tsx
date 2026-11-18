"use client";

import React, { useState } from "react";
import { CheckCircle2, Database, Download, FolderPlus, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/AppShell";
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
  NewLogVerifyResponse,
  PrivateZeekCaseDetail,
  PrivateZeekCaseItem,
} from "@/lib/types";
import { downloadBlob, formatNumber } from "@/lib/utils";

export default function NewLogReviewPage() {
  const [tab, setTab] = useState<"verify" | "readonly-db">("verify");

  // Step 1A-1D Verification state
  const [logFile, setLogFile] = useState<File | null>(null);
  const [reportFile, setReportFile] = useState<File | null>(null);
  const [modelPath, setModelPath] = useState("");
  const [modelSha, setModelSha] = useState("");
  const [logSha, setLogSha] = useState("");
  const [manifestPath, setManifestPath] = useState("");
  const [manifestSha, setManifestSha] = useState("");
  const [cidrInput, setCidrInput] = useState("192.168.56.0/24");
  const [pcapReportPath, setPcapReportPath] = useState("");
  const [pcapReportSha, setPcapReportSha] = useState("");
  const [pcapPath, setPcapPath] = useState("");

  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifiedResult, setVerifiedResult] = useState<NewLogVerifyResponse | null>(null);

  // Manual case creation state
  const [selectedRecordIndex, setSelectedRecordIndex] = useState<number>(0);
  const [dbPath, setDbPath] = useState("");
  const [rqPath, setRqPath] = useState("");
  const [rqSha, setRqSha] = useState("");
  const [rqRef, setRqRef] = useState("");
  const [att1, setAtt1] = useState(false);
  const [att2, setAtt2] = useState(false);
  const [att3, setAtt3] = useState(false);
  const [creatingCase, setCreatingCase] = useState(false);
  const [caseMsg, setCaseMsg] = useState<string | null>(null);
  const [caseErr, setCaseErr] = useState<string | null>(null);

  // Read-only SQLite browser state
  const [viewerDbPath, setViewerDbPath] = useState("");
  const [loadingDb, setLoadingDb] = useState(false);
  const [viewerErr, setViewerErr] = useState<string | null>(null);
  const [privateCases, setPrivateCases] = useState<PrivateZeekCaseItem[] | null>(null);
  const [privateLimited, setPrivateLimited] = useState(false);
  const [selectedPrivateCaseId, setSelectedPrivateCaseId] = useState<number | null>(null);
  const [privateDetail, setPrivateDetail] = useState<PrivateZeekCaseDetail | null>(null);

  const handleVerifySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setVerifyError(null);
    setCaseMsg(null);
    if (!logFile || !reportFile) {
      setVerifyError("Cần chọn đủ tệp NEW Zeek conn.log và NEW-log prediction JSON.");
      return;
    }
    setVerifying(true);
    try {
      const form = new FormData();
      form.append("log_file", logFile);
      form.append("report_file", reportFile);
      form.append("model_path", modelPath.trim());
      form.append("expected_model_sha256", modelSha.trim());
      form.append("expected_log_sha256", logSha.trim());
      form.append("manifest_path", manifestPath.trim());
      form.append("expected_manifest_sha256", manifestSha.trim());
      form.append("cidr_input", cidrInput.trim());
      form.append("offline_import_report_path", pcapReportPath.trim());
      form.append("offline_import_report_sha256", pcapReportSha.trim());
      form.append("offline_import_pcap_path", pcapPath.trim());
      const res = await api.verifyNewLogReview(form);
      setVerifiedResult(res);
      if (res.candidates.length > 0) {
        setSelectedRecordIndex(res.candidates[0].record_index);
      }
    } catch (err) {
      setVerifiedResult(null);
      setVerifyError(
        err instanceof Error
          ? err.message
          : "Từ chối xác minh. Kiểm tra tệp và SHA-256 riêng tư."
      );
    } finally {
      setVerifying(false);
    }
  };

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verifiedResult) return;
    setCaseErr(null);
    setCaseMsg(null);
    setCreatingCase(true);
    try {
      const form = new FormData();
      form.append("review_token", verifiedResult.review_token);
      form.append("db_path", dbPath.trim());
      form.append("record_index", String(selectedRecordIndex));
      form.append("analyst_confirmed", String(att1));
      form.append("operator_confirmed_authorized", String(att2));
      form.append("operator_confirmed_new_capture", String(att3));
      form.append("research_queue_path", rqPath.trim());
      form.append("research_queue_sha", rqSha.trim());
      form.append("research_queue_ref", rqRef.trim());
      const res = await api.createNewLogCase(form);
      setCaseMsg(res.message);
    } catch (err) {
      setCaseErr(
        err instanceof Error ? err.message : "Từ chối ghi hồ sơ SOC riêng tư."
      );
    } finally {
      setCreatingCase(false);
    }
  };

  const loadPrivateDetail = async (path: string, caseId: number) => {
    setSelectedPrivateCaseId(caseId);
    try {
      const detail = await api.getPrivateZeekCaseDetail(path, caseId);
      setPrivateDetail(detail);
    } catch (err) {
      setViewerErr(err instanceof Error ? err.message : "Không thể đọc chi tiết case");
    }
  };

  return (
    <AppShell
      title="New Log Review · Pinned SHA-256 AI Review"
      breadcrumb="Blue Team / New Log Review"
      provenanceTag="PINNED OFFLINE GATE"
    >
      <ModeBanner
        variant="blue"
        tag="FAIL-CLOSED SHA-256 GATE"
        title="Xác minh NEW conn.log tách biệt hoàn toàn với tập TRAIN/VALIDATION/TEST"
        description="Yêu cầu tệp model JSON, manifest và cơ sở dữ liệu SQLite riêng tư nằm ngoài thư mục Git. Không tự động phát cảnh báo hay suy đoán khi thiếu bằng chứng hash."
      />

      {/* Tabs */}
      <div className="flex gap-1.5 border-b border-slate-800 pb-2">
        <button
          type="button"
          onClick={() => setTab("verify")}
          className={`rounded-lg px-3.5 py-2 text-xs font-semibold ${
            tab === "verify"
              ? "bg-teal-600/25 text-teal-200 ring-1 ring-inset ring-teal-500/40"
              : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-100"
          }`}
        >
          1. Xác minh &amp; Đánh giá NEW Log
        </button>
        <button
          type="button"
          onClick={() => setTab("readonly-db")}
          className={`rounded-lg px-3.5 py-2 text-xs font-semibold ${
            tab === "readonly-db"
              ? "bg-teal-600/25 text-teal-200 ring-1 ring-inset ring-teal-500/40"
              : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-100"
          }`}
        >
          2. Hồ sơ SOC riêng tư (Chỉ đọc SQLite)
        </button>
      </div>

      {tab === "verify" ? (
        <div className="space-y-4">
          <form onSubmit={handleVerifySubmit} className="space-y-4">
            <Panel className="space-y-4">
              <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
                <span className="rounded bg-blue-600/20 px-2 py-0.5 font-mono text-[11px] font-bold text-blue-300">
                  BƯỚC 1A
                </span>
                <h2 className="text-sm font-semibold text-slate-100">
                  Tệp NEW Zeek conn.log &amp; Báo cáo dự đoán JSON
                </h2>
              </div>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <div>
                  <label className="mb-1 block text-xs text-slate-300">
                    NEW Zeek ASCII conn.log (tối đa 15 MiB)
                  </label>
                  <input
                    type="file"
                    accept=".log,.tsv,.txt"
                    onChange={(e) => setLogFile(e.target.files?.[0] ?? null)}
                    className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-1.5 text-xs text-slate-200 file:mr-3 file:rounded-md file:border-0 file:bg-teal-600/25 file:px-2.5 file:py-1 file:text-xs file:font-semibold file:text-teal-200 hover:file:bg-teal-600/40"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs text-slate-300">
                    NEW-log prediction JSON (tối đa 16 MiB)
                  </label>
                  <input
                    type="file"
                    accept=".json,application/json"
                    onChange={(e) => setReportFile(e.target.files?.[0] ?? null)}
                    className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-1.5 text-xs text-slate-200 file:mr-3 file:rounded-md file:border-0 file:bg-teal-600/25 file:px-2.5 file:py-1 file:text-xs file:font-semibold file:text-teal-200 hover:file:bg-teal-600/40"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2 border-b border-slate-800 pb-2 pt-2">
                <span className="rounded bg-blue-600/20 px-2 py-0.5 font-mono text-[11px] font-bold text-blue-300">
                  BƯỚC 1B
                </span>
                <h2 className="text-sm font-semibold text-slate-100">
                  Mô hình riêng tư &amp; SHA-256 ghi độc lập
                </h2>
              </div>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                <div>
                  <label className="mb-1 block text-xs text-slate-300">
                    Đường dẫn tuyệt đối Model JSON riêng tư
                  </label>
                  <input
                    type="text"
                    value={modelPath}
                    onChange={(e) => setModelPath(e.target.value)}
                    placeholder="C:/DA005-private/zeek-experiment/zeek-research-model.json"
                    className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-xs text-slate-100"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs text-slate-300">
                    Model SHA-256 (64 hex thường)
                  </label>
                  <input
                    type="text"
                    maxLength={64}
                    value={modelSha}
                    onChange={(e) => setModelSha(e.target.value)}
                    placeholder="64 ký tự hex..."
                    className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-xs text-slate-100"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs text-slate-300">
                    NEW-log SHA-256 (64 hex thường)
                  </label>
                  <input
                    type="text"
                    maxLength={64}
                    value={logSha}
                    onChange={(e) => setLogSha(e.target.value)}
                    placeholder="64 ký tự hex..."
                    className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-xs text-slate-100"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2 border-b border-slate-800 pb-2 pt-2">
                <span className="rounded bg-blue-600/20 px-2 py-0.5 font-mono text-[11px] font-bold text-blue-300">
                  BƯỚC 1C
                </span>
                <h2 className="text-sm font-semibold text-slate-100">
                  Manifest phân vùng TRAIN/VALIDATION/TEST &amp; CIDR Lab
                </h2>
              </div>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                <div>
                  <label className="mb-1 block text-xs text-slate-300">
                    Đường dẫn Manifest JSON riêng tư
                  </label>
                  <input
                    type="text"
                    value={manifestPath}
                    onChange={(e) => setManifestPath(e.target.value)}
                    placeholder="C:/DA005-private/zeek-experiment/manifest.json"
                    className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-xs text-slate-100"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs text-slate-300">
                    Manifest SHA-256 (64 hex thường)
                  </label>
                  <input
                    type="text"
                    maxLength={64}
                    value={manifestSha}
                    onChange={(e) => setManifestSha(e.target.value)}
                    placeholder="64 ký tự hex..."
                    className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-xs text-slate-100"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs text-slate-300">
                    CIDR Host-only được phép (1–4 dải)
                  </label>
                  <input
                    type="text"
                    value={cidrInput}
                    onChange={(e) => setCidrInput(e.target.value)}
                    placeholder="192.168.56.0/24"
                    className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-xs text-slate-100"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2 border-b border-slate-800 pb-2 pt-2">
                <span className="rounded bg-slate-700 px-2 py-0.5 font-mono text-[11px] font-bold text-slate-200">
                  BƯỚC 1D (TÙY CHỌN)
                </span>
                <h2 className="text-sm font-semibold text-slate-100">
                  Đối chiếu PCAP gốc đã import offline (All-or-None)
                </h2>
              </div>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                <input
                  type="text"
                  value={pcapReportPath}
                  onChange={(e) => setPcapReportPath(e.target.value)}
                  placeholder="Đường dẫn offline_import_report.json"
                  className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-xs text-slate-100"
                />
                <input
                  type="text"
                  maxLength={64}
                  value={pcapReportSha}
                  onChange={(e) => setPcapReportSha(e.target.value)}
                  placeholder="SHA-256 báo cáo import (64 hex)"
                  className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-xs text-slate-100"
                />
                <input
                  type="text"
                  value={pcapPath}
                  onChange={(e) => setPcapPath(e.target.value)}
                  placeholder="Đường dẫn original.pcap"
                  className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-xs text-slate-100"
                />
              </div>

              <div className="flex justify-end pt-2">
                <button
                  type="submit"
                  disabled={verifying}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-teal-600 px-4 py-2 text-xs font-semibold text-white hover:bg-teal-500 disabled:opacity-50"
                >
                  <ShieldCheck className="h-4 w-4" />
                  {verifying ? "Đang xác minh SHA-256 & phân vùng..." : "Xác minh và xem ứng viên nghiên cứu"}
                </button>
              </div>
            </Panel>
          </form>

          {verifyError && <ErrorBanner message={verifyError} />}

          {verifiedResult && (
            <div className="space-y-4">
              <SuccessBanner message="Đã đối chiếu phân vùng khai báo và tính lại toàn bộ dự đoán từ model/log đã ghim." />
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <KpiCard label="Flow đã xác minh" value={formatNumber(verifiedResult.flow_count)} accent="teal" />
                <KpiCard
                  label="Ứng viên nghiên cứu"
                  value={formatNumber(verifiedResult.research_candidate_count)}
                  accent="amber"
                />
                <KpiCard
                  label="Cửa sổ hiển thị"
                  value={`${formatNumber(verifiedResult.visible_flow_count)} flows`}
                  sublabel={`Ngưỡng validation: ${verifiedResult.validation_threshold.toFixed(4)}`}
                  accent="blue"
                />
              </div>

              <Panel>
                <h3 className="mb-2 text-sm font-semibold text-slate-100">
                  2. Ứng viên AI trong 500 dòng đầu (Không hiển thị ground truth)
                </h3>
                {verifiedResult.candidates.length === 0 ? (
                  <EmptyState
                    title="Không có ứng viên vượt ngưỡng trong 500 dòng đầu"
                    description="Xác minh phân vùng thành công nhưng chưa có flow ứng viên trong cửa sổ hiển thị."
                  />
                ) : (
                  <div className="max-h-72 overflow-auto rounded-lg border border-slate-800">
                    <table className="w-full border-collapse text-left text-xs font-mono">
                      <thead className="bg-subtle text-[11px] text-slate-400">
                        <tr>
                          <th className="px-3 py-2">Dòng Zeek</th>
                          <th className="px-3 py-2">UID</th>
                          <th className="px-3 py-2">P(Attack)</th>
                          <th className="px-3 py-2">Ưu tiên</th>
                          <th className="px-3 py-2">Src &rarr; Dst</th>
                          <th className="px-3 py-2">UTC</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800">
                        {verifiedResult.candidates.map((c) => (
                          <tr key={c.uid}>
                            <td className="px-3 py-1.5 text-slate-300">{c.zeek_row}</td>
                            <td className="px-3 py-1.5 text-teal-300">{c.uid}</td>
                            <td className="px-3 py-1.5 text-slate-100">
                              {(c.attack_probability * 100).toFixed(2)}%
                            </td>
                            <td className="px-3 py-1.5">
                              <PriorityBadge code={c.priority_band.code} label={c.priority_band.label} />
                            </td>
                            <td className="px-3 py-1.5 text-slate-300">
                              {c.src_ip} &rarr; {c.dst_ip}
                            </td>
                            <td className="px-3 py-1.5 text-slate-400">{c.event_time_utc}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Panel>

              {verifiedResult.candidates.length > 0 && (
                <Panel>
                  <form onSubmit={handleCreateCase} className="space-y-3 text-xs">
                    <h3 className="text-sm font-semibold text-slate-100">
                      3. Tạo hoặc tái sử dụng hồ sơ SOC thủ công (Unclassified)
                    </h3>
                    {caseMsg && <SuccessBanner message={caseMsg} />}
                    {caseErr && <ErrorBanner message={caseErr} />}
                    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                      <div>
                        <label className="mb-1 block text-slate-300">Ứng viên đã xem xét</label>
                        <select
                          value={selectedRecordIndex}
                          onChange={(e) => setSelectedRecordIndex(Number(e.target.value))}
                          className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-slate-100"
                        >
                          {verifiedResult.candidates.map((c) => (
                            <option key={c.uid} value={c.record_index}>
                              Zeek row {c.zeek_row} · P(Attack) {c.attack_probability.toFixed(4)}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="mb-1 block text-slate-300">
                          Đường dẫn SQLite SOC riêng tư ngoài Git (.sqlite3)
                        </label>
                        <input
                          type="text"
                          required
                          value={dbPath}
                          onChange={(e) => setDbPath(e.target.value)}
                          placeholder="C:/DA005-private/soc/cyber_lab_cases.sqlite3"
                          className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-slate-100"
                        />
                      </div>
                    </div>
                    <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                      <input
                        type="text"
                        value={rqPath}
                        onChange={(e) => setRqPath(e.target.value)}
                        placeholder="Research queue JSON (tùy chọn)"
                        className="rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-slate-100"
                      />
                      <input
                        type="text"
                        maxLength={64}
                        value={rqSha}
                        onChange={(e) => setRqSha(e.target.value)}
                        placeholder="Research queue SHA-256 (tùy chọn)"
                        className="rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-slate-100"
                      />
                      <input
                        type="text"
                        maxLength={64}
                        value={rqRef}
                        onChange={(e) => setRqRef(e.target.value)}
                        placeholder="Research alert reference (tùy chọn)"
                        className="rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-slate-100"
                      />
                    </div>
                    <div className="space-y-1.5 text-slate-300">
                      <label className="flex cursor-pointer items-center gap-2">
                        <input type="checkbox" checked={att1} onChange={(e) => setAtt1(e.target.checked)} />
                        Tôi đã xem log gốc và bằng chứng của flow này.
                      </label>
                      <label className="flex cursor-pointer items-center gap-2">
                        <input type="checkbox" checked={att2} onChange={(e) => setAtt2(e.target.checked)} />
                        Tôi xác nhận có quyền sử dụng dữ liệu và phạm vi lab.
                      </label>
                      <label className="flex cursor-pointer items-center gap-2">
                        <input type="checkbox" checked={att3} onChange={(e) => setAtt3(e.target.checked)} />
                        Tôi xác nhận NEW log không thuộc TRAIN/VALIDATION/TEST đã đăng ký.
                      </label>
                    </div>
                    <button
                      type="submit"
                      disabled={creatingCase || !att1 || !att2 || !att3}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 font-semibold text-white hover:bg-blue-500 disabled:opacity-40"
                    >
                      <FolderPlus className="h-3.5 w-3.5" />
                      {creatingCase ? "Đang ghi SQLite..." : "Tạo hoặc tái sử dụng hồ sơ Unclassified"}
                    </button>
                  </form>
                </Panel>
              )}
            </div>
          )}
        </div>
      ) : (
        <div className="space-y-4">
          <Panel>
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <div className="flex-1">
                <label className="mb-1 block text-xs font-medium text-slate-300">
                  Đường dẫn tuyệt đối tới SQLite SOC riêng tư ngoài Git (.sqlite3)
                </label>
                <input
                  type="text"
                  value={viewerDbPath}
                  onChange={(e) => setViewerDbPath(e.target.value)}
                  placeholder="C:/DA005-private/soc/cyber_lab_cases.sqlite3"
                  className="w-full rounded-lg border border-slate-700 bg-canvas px-3 py-2 font-mono text-xs text-slate-100"
                />
              </div>
              <button
                type="button"
                disabled={loadingDb || !viewerDbPath.trim()}
                onClick={async () => {
                  setLoadingDb(true);
                  setViewerErr(null);
                  setPrivateDetail(null);
                  try {
                    const res = await api.listPrivateZeekCases(viewerDbPath.trim());
                    setPrivateCases(res.cases);
                    setPrivateLimited(res.limited);
                    if (res.cases.length > 0) {
                      await loadPrivateDetail(viewerDbPath.trim(), res.cases[0].case_id);
                    }
                  } catch (err) {
                    setPrivateCases(null);
                    setViewerErr(
                      err instanceof Error ? err.message : "Không thể đọc SQLite riêng tư"
                    );
                  } finally {
                    setLoadingDb(false);
                  }
                }}
                className="inline-flex items-center gap-1.5 rounded-lg bg-teal-600 px-4 py-2 text-xs font-semibold text-white hover:bg-teal-500 disabled:opacity-40"
              >
                <Database className="h-3.5 w-3.5" />
                {loadingDb ? "Đang đọc..." : "Đọc danh sách hồ sơ (Chỉ đọc)"}
              </button>
            </div>
          </Panel>

          {viewerErr && <ErrorBanner message={viewerErr} />}

          {privateCases === null ? (
            <EmptyState
              title="Trình đọc hồ sơ SOC nghiên cứu (Read-Only)"
              description="Mở kết nối SQLite ở chế độ mode=ro & query_only=ON để xem lại snapshot flow và audit trail của các case Unclassified mà không cần nạp lại model."
            />
          ) : privateCases.length === 0 ? (
            <EmptyState
              title="Không có hồ sơ Zeek Unclassified phù hợp"
              description="Cơ sở dữ liệu SQLite được chọn chưa có hồ sơ Zeek Unclassified nào trong phạm vi đọc."
            />
          ) : (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
              <Panel className="lg:col-span-5">
                <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
                  <span>Hồ sơ Zeek ({privateCases.length})</span>
                  {privateLimited && <span>(Giới hạn 100 hồ sơ gần nhất)</span>}
                </div>
                <div className="max-h-96 space-y-2 overflow-y-auto">
                  {privateCases.map((item) => (
                    <button
                      key={item.case_id}
                      type="button"
                      onClick={() => void loadPrivateDetail(viewerDbPath.trim(), item.case_id)}
                      className={`w-full rounded-lg border p-2.5 text-left text-xs ${
                        selectedPrivateCaseId === item.case_id
                          ? "border-teal-500/60 bg-teal-950/35"
                          : "border-slate-800 bg-canvas hover:bg-slate-800/40"
                      }`}
                    >
                      <div className="flex items-center justify-between font-mono font-semibold text-teal-300">
                        <span>Case #{item.case_id}</span>
                        <span>{item.zeek_uid ?? "—"}</span>
                      </div>
                      <div className="mt-1 truncate font-mono text-[10px] text-slate-400">
                        SHA: {item.source_sha256 ?? "—"}
                      </div>
                    </button>
                  ))}
                </div>
              </Panel>

              <Panel className="lg:col-span-7">
                {privateDetail ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                      <div className="flex items-center gap-2 font-mono text-sm font-bold text-slate-100">
                        <CheckCircle2 className="h-4 w-4 text-teal-400" />
                        Case #{selectedPrivateCaseId} (Unclassified · Read-only)
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          const blob = new Blob([JSON.stringify(privateDetail, null, 2)], {
                            type: "application/json",
                          });
                          downloadBlob(blob, `zeek-research-case-${selectedPrivateCaseId}.json`);
                        }}
                        className="inline-flex items-center gap-1 rounded border border-slate-700 bg-subtle px-2.5 py-1 text-xs text-slate-200 hover:bg-slate-800"
                      >
                        <Download className="h-3.5 w-3.5" />
                        Tải JSON
                      </button>
                    </div>
                    <pre className="max-h-56 overflow-auto rounded-lg border border-slate-800 bg-canvas p-3 font-mono text-[11px] text-slate-300">
                      {JSON.stringify(privateDetail.flow_evidence, null, 2)}
                    </pre>
                    <div className="max-h-48 overflow-auto rounded-lg border border-slate-800">
                      <table className="w-full border-collapse text-left text-xs font-mono">
                        <thead className="bg-subtle text-[11px] text-slate-400">
                          <tr>
                            <th className="px-2.5 py-1.5">Event</th>
                            <th className="px-2.5 py-1.5">State</th>
                            <th className="px-2.5 py-1.5">Note</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800">
                          {privateDetail.case_events.map((ev, i) => (
                            <tr key={i}>
                              <td className="px-2.5 py-1.5 text-slate-400">#{String(ev.event_id)}</td>
                              <td className="px-2.5 py-1.5 text-teal-300">{String(ev.new_state)}</td>
                              <td className="px-2.5 py-1.5 font-sans text-slate-300">{String(ev.note)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : null}
              </Panel>
            </div>
          )}
        </div>
      )}
    </AppShell>
  );
}
