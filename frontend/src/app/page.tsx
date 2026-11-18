"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Upload } from "lucide-react";
import { AppShell } from "@/components/AppShell";
import {
  FlowInspectorDrawer,
  type InspectorPayload,
} from "@/components/FlowInspectorDrawer";
import {
  AlertsTab,
  CasesTab,
} from "@/components/dataset/AlertsAndCasesTabs";
import { EvaluationTab } from "@/components/dataset/EvaluationTab";
import {
  HuntingTab,
  type HuntingFilters,
} from "@/components/dataset/HuntingTab";
import { OverviewTab } from "@/components/dataset/OverviewTab";
import {
  ErrorBanner,
  LoadingRows,
  ModeBanner,
  Panel,
  SuccessBanner,
} from "@/components/ui";
import { api } from "@/lib/api";
import type {
  DatasetAlertsResponse,
  DatasetEvaluationResponse,
  DatasetHuntingResponse,
  DatasetOverviewResponse,
  FlowRow,
  SocCaseDetailResponse,
  SocCaseSummary,
} from "@/lib/types";
import { downloadBlob, formatNumber } from "@/lib/utils";

type DatasetTab = "overview" | "hunting" | "evaluation" | "alerts" | "cases";

const DEFAULT_FILTERS: HuntingFilters = {
  protocols: [],
  services: [],
  states: [],
  onlyAiAttacks: false,
  minProbEnabled: false,
  minProb: 0.8,
  search: "",
  sortBy: "row_index",
  sortDir: "asc",
  page: 1,
  pageSize: 25,
};

export default function DatasetSocPage() {
  const [source, setSource] = useState<"official" | "upload">("official");
  const [sampleSize, setSampleSize] = useState<number>(2500);
  const [uploadId, setUploadId] = useState<string | null>(null);
  const [uploadedFilename, setUploadedFilename] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<DatasetTab>("overview");
  const [overview, setOverview] = useState<DatasetOverviewResponse | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(true);
  const [overviewError, setOverviewError] = useState<string | null>(null);

  const [filters, setFilters] = useState<HuntingFilters>(DEFAULT_FILTERS);
  const [hunting, setHunting] = useState<DatasetHuntingResponse | null>(null);
  const [huntingLoading, setHuntingLoading] = useState(false);

  const [evaluation, setEvaluation] = useState<DatasetEvaluationResponse | null>(null);
  const [evaluationLoading, setEvaluationLoading] = useState(false);

  const [alertThreshold, setAlertThreshold] = useState(0.8);
  const [alertPriority, setAlertPriority] = useState("ALL");
  const [alerts, setAlerts] = useState<DatasetAlertsResponse | null>(null);
  const [alertsLoading, setAlertsLoading] = useState(false);

  const [cases, setCases] = useState<SocCaseSummary[]>([]);
  const [caseStates, setCaseStates] = useState<string[]>([
    "New",
    "Investigating",
    "Escalated",
    "Resolved",
    "False Positive",
  ]);
  const [caseStateFilter, setCaseStateFilter] = useState("ALL");
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(null);
  const [caseDetail, setCaseDetail] = useState<SocCaseDetailResponse | null>(null);
  const [loadingCaseDetail, setLoadingCaseDetail] = useState(false);

  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [inspector, setInspector] = useState<InspectorPayload | null>(null);

  const loadOverview = useCallback(async () => {
    if (source === "upload" && !uploadId) {
      setOverview(null);
      setOverviewLoading(false);
      return;
    }
    setOverviewLoading(true);
    setOverviewError(null);
    try {
      const data = await api.getDatasetOverview({
        source,
        sample_size: sampleSize,
        upload_id: uploadId,
      });
      setOverview(data);
    } catch (err) {
      setOverviewError(
        err instanceof Error ? err.message : "Không thể tải tổng quan dữ liệu"
      );
    } finally {
      setOverviewLoading(false);
    }
  }, [source, sampleSize, uploadId]);

  const loadHunting = useCallback(async () => {
    if (source === "upload" && !uploadId) return;
    setHuntingLoading(true);
    try {
      const data = await api.getDatasetHunting({
        source,
        sample_size: sampleSize,
        upload_id: uploadId,
        protocols: filters.protocols,
        services: filters.services,
        states: filters.states,
        only_ai_attacks: filters.onlyAiAttacks,
        min_attack_probability: filters.minProbEnabled ? filters.minProb : null,
        search: filters.search,
        sort_by: filters.sortBy,
        sort_dir: filters.sortDir,
        page: filters.page,
        page_size: filters.pageSize,
      });
      setHunting(data);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Không thể lọc Threat hunting");
    } finally {
      setHuntingLoading(false);
    }
  }, [source, sampleSize, uploadId, filters]);

  const loadEvaluation = useCallback(async () => {
    if (source === "upload" && !uploadId) return;
    setEvaluationLoading(true);
    try {
      const data = await api.getDatasetEvaluation({
        source,
        sample_size: sampleSize,
        upload_id: uploadId,
      });
      setEvaluation(data);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Không thể tải đánh giá mô hình");
    } finally {
      setEvaluationLoading(false);
    }
  }, [source, sampleSize, uploadId]);

  const loadAlerts = useCallback(async () => {
    if (source === "upload" && !uploadId) return;
    setAlertsLoading(true);
    try {
      const data = await api.getDatasetAlerts({
        source,
        sample_size: sampleSize,
        upload_id: uploadId,
        threshold: alertThreshold,
        priority: alertPriority,
      });
      setAlerts(data);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Không thể tải hàng đợi cảnh báo");
    } finally {
      setAlertsLoading(false);
    }
  }, [source, sampleSize, uploadId, alertThreshold, alertPriority]);

  const loadCases = useCallback(
    async (preferredCaseId?: number) => {
      try {
        const res = await api.listSocCases(caseStateFilter);
        setCases(res.cases);
        setCaseStates(res.case_states);
        const targetId =
          preferredCaseId ??
          (selectedCaseId && res.cases.some((c) => c.case_id === selectedCaseId)
            ? selectedCaseId
            : res.cases[0]?.case_id ?? null);
        setSelectedCaseId(targetId);
        if (targetId !== null) {
          setLoadingCaseDetail(true);
          try {
            const detail = await api.getSocCaseDetail(targetId);
            setCaseDetail(detail);
          } finally {
            setLoadingCaseDetail(false);
          }
        } else {
          setCaseDetail(null);
        }
      } catch (err) {
        setActionError(err instanceof Error ? err.message : "Không thể tải danh sách hồ sơ SOC");
      }
    },
    [caseStateFilter, selectedCaseId]
  );

  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  useEffect(() => {
    if (activeTab === "hunting") void loadHunting();
    if (activeTab === "evaluation") void loadEvaluation();
    if (activeTab === "alerts") void loadAlerts();
    if (activeTab === "cases") void loadCases();
  }, [activeTab, loadHunting, loadEvaluation, loadAlerts, loadCases]);

  const handleCsvUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    try {
      const res = await api.uploadDatasetCsv(file, sampleSize);
      setUploadId(res.upload_id);
      setUploadedFilename(res.filename);
      setSource("upload");
      setFilters(DEFAULT_FILTERS);
      setToastMsg(
        `Đã nạp ${formatNumber(res.rows_loaded)} dòng từ ${res.filename} (SHA-256: ${res.sha256.slice(0, 12)}...).`
      );
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : "Tải lên CSV thất bại");
    } finally {
      setUploading(false);
      e.target.value = "";
    }
  };

  const handleCreateCaseFromFlow = async (row: FlowRow) => {
    setActionError(null);
    const created = await api.createSocCase({
      source,
      sample_size: sampleSize,
      upload_id: uploadId,
      row_index: row.row_index,
      flow_ref: row.flow_ref,
    });
    setToastMsg(created.message);
    setInspector(null);
    await loadOverview();
    setActiveTab("cases");
    await loadCases(created.case_id);
  };

  const openInspector = (row: FlowRow) => {
    setInspector({
      title: `Flow ${row.flow_ref}`,
      subtitle: `Bản ghi #${row.row_index + 1} · ${row.proto ?? "—"} / ${row.service ?? "—"} · State: ${row.state ?? "—"}`,
      badgeCode: row.priority_band.code,
      badgeLabel: row.priority_band.label,
      signalScore: row.signal_score,
      signalReasons: row.signal_reasons,
      evidence: row.flow_evidence,
      canCreateCase: Boolean(overview?.provenance.predictions_available),
      onCreateCase: () => handleCreateCaseFromFlow(row),
    });
  };

  return (
    <AppShell
      title="Security Operations Center — Dataset Mode"
      breadcrumb="Blue Team / Dataset SOC"
      provenanceTag={
        source === "official" ? "UNSW-NB15 TEST (OFFLINE)" : `CSV UPLOAD (${uploadedFilename ?? "CHƯA NẠP"})`
      }
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex rounded-lg border border-slate-700 bg-surface p-0.5 text-xs">
            <button
              type="button"
              onClick={() => {
                setSource("official");
                setFilters(DEFAULT_FILTERS);
              }}
              className={`rounded-md px-2.5 py-1 font-medium transition-colors ${
                source === "official"
                  ? "bg-blue-600 text-white"
                  : "text-slate-300 hover:text-white"
              }`}
            >
              UNSW-NB15 test
            </button>
            <button
              type="button"
              onClick={() => setSource("upload")}
              className={`rounded-md px-2.5 py-1 font-medium transition-colors ${
                source === "upload"
                  ? "bg-blue-600 text-white"
                  : "text-slate-300 hover:text-white"
              }`}
            >
              Tải lên CSV
            </button>
          </div>

          <label className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-surface px-2.5 py-1 text-xs text-slate-300">
            <span>Mẫu:</span>
            <select
              aria-label="Số bản ghi phân tích"
              value={sampleSize}
              onChange={(e) => {
                setSampleSize(Number(e.target.value));
                setFilters((prev) => ({ ...prev, page: 1 }));
              }}
              className="bg-transparent font-mono font-semibold text-slate-100 focus:outline-none"
            >
              {[500, 1000, 2500, 5000, 10000].map((n) => (
                <option key={n} value={n} className="bg-slate-900">
                  {formatNumber(n)} flows
                </option>
              ))}
            </select>
          </label>
        </div>
      }
    >
      <ModeBanner
        variant="dataset"
        tag="HISTORICAL DATASET · OFFLINE"
        title="Phạm vi dữ liệu nghiên cứu UNSW-NB15 (Ngoại tuyến)"
        description="Các bản ghi train/test UNSW-NB15 không chứa IP và timestamp sự kiện gốc; thứ tự dòng không phải chuỗi thời gian thực. Nhãn gốc (ground truth) không được đưa vào mô hình AI."
      />

      {source === "upload" && (
        <Panel>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="text-xs font-semibold text-slate-100">
                Nạp tệp CSV có cấu trúc UNSW-NB15 (tối đa 15 MiB)
              </div>
              <div className="text-xs text-slate-400">
                Kiểm tra nghiêm ngặt UTF-8, byte NUL, tiêu đề trùng và số cột trên toàn tệp trước khi suy luận.
              </div>
            </div>
            <label className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-blue-500/40 bg-blue-600/20 px-3.5 py-2 text-xs font-semibold text-blue-200 hover:bg-blue-600/30">
              <Upload className="h-3.5 w-3.5" />
              {uploading ? "Đang kiểm tra & đọc CSV..." : "Chọn tệp CSV từ máy"}
              <input
                type="file"
                accept=".csv,text/csv"
                disabled={uploading}
                onChange={handleCsvUpload}
                className="sr-only"
              />
            </label>
          </div>
          {uploadError && (
            <div className="mt-3">
              <ErrorBanner message={uploadError} />
            </div>
          )}
        </Panel>
      )}

      {toastMsg && <SuccessBanner message={toastMsg} />}
      {actionError && <ErrorBanner message={actionError} onRetry={() => setActionError(null)} />}
      {overviewError && <ErrorBanner message={overviewError} onRetry={() => void loadOverview()} />}

      {/* Tab navigation */}
      <div
        role="tablist"
        aria-label="Các phân hệ Dataset SOC"
        className="flex gap-1.5 overflow-x-auto border-b border-slate-800 pb-2"
      >
        {(
          [
            { id: "overview", label: "Tổng quan an ninh" },
            { id: "hunting", label: "Threat hunting" },
            { id: "evaluation", label: "AI & đánh giá" },
            { id: "alerts", label: "Trung tâm cảnh báo" },
            { id: "cases", label: "SOC case management" },
          ] as const
        ).map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={activeTab === tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`whitespace-nowrap rounded-lg px-3.5 py-2 text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
              activeTab === tab.id
                ? "bg-blue-600/25 text-blue-200 ring-1 ring-inset ring-blue-500/50"
                : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-100"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab body */}
      {overviewLoading && !overview ? (
        <LoadingRows count={6} />
      ) : source === "upload" && !uploadId ? (
        <Panel>
          <p className="text-xs text-slate-300">
            Hãy chọn một tệp CSV hợp lệ ở bảng phía trên để bắt đầu phân tích, hoặc chuyển về{" "}
            <strong className="text-slate-100">UNSW-NB15 test</strong>.
          </p>
        </Panel>
      ) : (
        <>
          {activeTab === "overview" && overview && (
            <OverviewTab
              data={overview}
              onSelectTab={(tab, cid) => {
                setActiveTab(tab);
                if (tab === "cases" && cid) {
                  setSelectedCaseId(cid);
                }
              }}
            />
          )}

          {activeTab === "hunting" && overview && (
            <HuntingTab
              data={hunting}
              loading={huntingLoading}
              filterOptions={overview.filter_options}
              filters={filters}
              predictionsAvailable={overview.provenance.predictions_available}
              onChangeFilters={(patch) => setFilters((prev) => ({ ...prev, ...patch }))}
              onResetFilters={() => setFilters(DEFAULT_FILTERS)}
              onExportCsv={async () => {
                try {
                  const blob = await api.exportHuntingCsvBlob({
                    source,
                    sample_size: sampleSize,
                    upload_id: uploadId,
                    protocols: filters.protocols,
                    services: filters.services,
                    states: filters.states,
                    only_ai_attacks: filters.onlyAiAttacks,
                    min_attack_probability: filters.minProbEnabled ? filters.minProb : null,
                    search: filters.search,
                  });
                  downloadBlob(blob, "da005_hunting_results.csv");
                } catch (err) {
                  setActionError(err instanceof Error ? err.message : "Xuất CSV thất bại");
                }
              }}
              onInspectRow={openInspector}
            />
          )}

          {activeTab === "evaluation" &&
            (evaluationLoading && !evaluation ? (
              <LoadingRows count={6} />
            ) : (
              evaluation && <EvaluationTab data={evaluation} />
            ))}

          {activeTab === "alerts" && (
            <AlertsTab
              data={alerts}
              loading={alertsLoading}
              threshold={alertThreshold}
              priority={alertPriority}
              onChangeThreshold={setAlertThreshold}
              onChangePriority={setAlertPriority}
              onCreateCase={handleCreateCaseFromFlow}
              onInspectRow={openInspector}
            />
          )}

          {activeTab === "cases" && (
            <CasesTab
              cases={cases}
              caseStates={caseStates}
              stateFilter={caseStateFilter}
              selectedCaseId={selectedCaseId}
              caseDetail={caseDetail}
              loadingDetail={loadingCaseDetail}
              onChangeStateFilter={(st) => {
                setCaseStateFilter(st);
              }}
              onSelectCase={async (cid) => {
                setSelectedCaseId(cid);
                setLoadingCaseDetail(true);
                try {
                  const detail = await api.getSocCaseDetail(cid);
                  setCaseDetail(detail);
                } finally {
                  setLoadingCaseDetail(false);
                }
              }}
              onUpdateCase={async (cid, st, note) => {
                await api.updateSocCase(cid, { state: st, analyst_note: note });
                await loadCases(cid);
              }}
              onExportCase={async (cid) => {
                try {
                  const blob = await api.exportSocCaseBlob(cid);
                  downloadBlob(blob, `da005_soc_case_${cid}.json`);
                } catch (err) {
                  setActionError(err instanceof Error ? err.message : "Xuất JSON thất bại");
                }
              }}
            />
          )}
        </>
      )}

      <FlowInspectorDrawer payload={inspector} onClose={() => setInspector(null)} />
    </AppShell>
  );
}
