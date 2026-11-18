import type {
  CyberLabParseResponse,
  CyberLabTraceResponse,
  DatasetAlertsResponse,
  DatasetEvaluationResponse,
  DatasetHuntingResponse,
  DatasetOverviewResponse,
  NewLogVerifyResponse,
  PrivateZeekCaseDetail,
  PrivateZeekCaseItem,
  RedTeamBenchmarkResponse,
  RedTeamStateResponse,
  SocCaseDetailResponse,
  SocCaseSummary,
  SystemStatus,
} from "./types";

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000/api/v1";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status = 500) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      cache: "no-store",
    });
  } catch {
    throw new ApiError(
      `Không thể kết nối đến Backend API (${API_BASE_URL}). Kiểm tra máy chủ FastAPI đang chạy ở cổng 8000.`,
      0
    );
  }
  if (!response.ok) {
    let message = `Yêu cầu thất bại (HTTP ${response.status})`;
    try {
      const errBody = await response.json();
      if (errBody && typeof errBody.detail === "string") {
        message = errBody.detail;
      }
    } catch {
      // keep default status error message
    }
    throw new ApiError(message, response.status);
  }
  return (await response.json()) as T;
}

function buildDatasetParams(params: Record<string, unknown>): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === null || v === undefined || v === "") continue;
    if (Array.isArray(v)) {
      for (const item of v) {
        if (item !== null && item !== undefined && item !== "") {
          qs.append(k, String(item));
        }
      }
    } else {
      qs.set(k, String(v));
    }
  }
  return qs.toString();
}

export const api = {
  getSystemStatus: () => request<SystemStatus>("/system/status"),

  uploadDatasetCsv: async (file: File, limit: number) => {
    const form = new FormData();
    form.append("file", file);
    form.append("limit", String(limit));
    return request<{
      upload_id: string;
      filename: string;
      sha256: string;
      rows_loaded: number;
      has_ground_truth_label: boolean;
    }>("/dataset/upload-csv", { method: "POST", body: form });
  },

  getDatasetOverview: (params: {
    source: "official" | "upload";
    sample_size: number;
    upload_id?: string | null;
  }) => request<DatasetOverviewResponse>(`/dataset/overview?${buildDatasetParams(params)}`),

  getDatasetHunting: (params: {
    source: "official" | "upload";
    sample_size: number;
    upload_id?: string | null;
    protocols: string[];
    services: string[];
    states: string[];
    only_ai_attacks: boolean;
    min_attack_probability?: number | null;
    search: string;
    sort_by: string;
    sort_dir: "asc" | "desc";
    page: number;
    page_size: number;
  }) => request<DatasetHuntingResponse>(`/dataset/hunting?${buildDatasetParams(params)}`),

  exportHuntingCsvBlob: async (params: {
    source: "official" | "upload";
    sample_size: number;
    upload_id?: string | null;
    protocols: string[];
    services: string[];
    states: string[];
    only_ai_attacks: boolean;
    min_attack_probability?: number | null;
    search: string;
  }) => {
    const resp = await fetch(
      `${API_BASE_URL}/dataset/hunting/export-csv?${buildDatasetParams(params)}`,
      { cache: "no-store" }
    );
    if (!resp.ok) throw new ApiError("Không thể xuất CSV kết quả lọc", resp.status);
    return await resp.blob();
  },

  getDatasetEvaluation: (params: {
    source: "official" | "upload";
    sample_size: number;
    upload_id?: string | null;
  }) => request<DatasetEvaluationResponse>(`/dataset/evaluation?${buildDatasetParams(params)}`),

  getDatasetAlerts: (params: {
    source: "official" | "upload";
    sample_size: number;
    upload_id?: string | null;
    threshold: number;
    priority: string;
    limit?: number;
  }) => request<DatasetAlertsResponse>(`/dataset/alerts?${buildDatasetParams(params)}`),

  listSocCases: (state = "ALL") =>
    request<{ cases: SocCaseSummary[]; case_states: string[] }>(
      `/soc/cases?state=${encodeURIComponent(state)}`
    ),

  createSocCase: (payload: {
    source: "official" | "upload";
    sample_size: number;
    upload_id?: string | null;
    row_index: number;
    flow_ref: string;
  }) =>
    request<{ case_id: number; message: string }>("/soc/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),

  getSocCaseDetail: (caseId: number) =>
    request<SocCaseDetailResponse>(`/soc/cases/${caseId}`),

  updateSocCase: (caseId: number, payload: { state: string; analyst_note: string }) =>
    request<{ case_id: number; state: string; message: string }>(`/soc/cases/${caseId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),

  exportSocCaseBlob: async (caseId: number) => {
    const resp = await fetch(`${API_BASE_URL}/soc/cases/${caseId}/export`, {
      cache: "no-store",
    });
    if (!resp.ok) throw new ApiError("Không thể xuất JSON hồ sơ", resp.status);
    return await resp.blob();
  },

  // Cyber Lab
  parseZeekLog: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<CyberLabParseResponse>("/cyber-lab/parse-log", {
      method: "POST",
      body: form,
    });
  },

  loadSampleZeekFixture: () =>
    request<CyberLabParseResponse>("/cyber-lab/load-sample-fixture", { method: "POST" }),

  reviewZeekTrace: (sourceSha256: string, traceFile: File) => {
    const form = new FormData();
    form.append("source_sha256", sourceSha256);
    form.append("trace_file", traceFile);
    return request<CyberLabTraceResponse>("/cyber-lab/review-trace", {
      method: "POST",
      body: form,
    });
  },

  createCyberLabManualCase: (payload: {
    source_sha256: string;
    record_index: number;
    consent: boolean;
  }) =>
    request<{
      case_id: number;
      verdict: string;
      verified_export: Record<string, unknown>;
    }>("/cyber-lab/manual-case", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),

  createCyberLabResearchCase: (payload: {
    source_sha256: string;
    trace_sha256: string;
    record_index: number;
    analyst_confirmed: boolean;
  }) =>
    request<{
      case_id: number;
      verdict: string;
      verified_export: Record<string, unknown>;
    }>("/cyber-lab/research-candidate-case", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),

  // Red Team Lab
  getRedTeamState: (sessionId = "default") =>
    request<RedTeamStateResponse>(
      `/red-team/state?session_id=${encodeURIComponent(sessionId)}`
    ),

  proposeRedTeamScenario: (payload: {
    session_id?: string;
    strategy: "ucb1" | "random";
    seed: number;
  }) =>
    request<RedTeamStateResponse>("/red-team/propose", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: "default", ...payload }),
    }),

  submitRedTeamFeedback: (payload: {
    session_id?: string;
    proposal_id: number;
    blue_flagged: boolean;
    confirm: boolean;
  }) =>
    request<RedTeamStateResponse>("/red-team/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: "default", ...payload }),
    }),

  resetRedTeamSession: (sessionId = "default") =>
    request<RedTeamStateResponse>("/red-team/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_id: sessionId }),
    }),

  runRedTeamSyntheticBenchmark: (payload: {
    rounds: number;
    trials: number;
    seed: number;
  }) =>
    request<RedTeamBenchmarkResponse>("/red-team/synthetic-benchmark", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),

  // New Log Review
  verifyNewLogReview: (form: FormData) =>
    request<NewLogVerifyResponse>("/new-log-review/verify", {
      method: "POST",
      body: form,
    }),

  createNewLogCase: (form: FormData) =>
    request<{ case_id: number; verdict: string; message: string }>(
      "/new-log-review/create-case",
      { method: "POST", body: form }
    ),

  listPrivateZeekCases: (dbPath: string) =>
    request<{ cases: PrivateZeekCaseItem[]; limited: boolean; scan_limit: number }>(
      "/new-log-review/private-cases/list",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ db_path: dbPath }),
      }
    ),

  getPrivateZeekCaseDetail: (dbPath: string, caseId: number) =>
    request<PrivateZeekCaseDetail>("/new-log-review/private-cases/detail", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ db_path: dbPath, case_id: caseId }),
    }),
};
