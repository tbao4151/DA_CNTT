export interface SystemStatus {
  status: string;
  mode: string;
  live_capture_enabled: boolean;
  red_team_execution_enabled: boolean;
  vmware_environment_status: string;
  dataset: {
    unsw_test_available: boolean;
    unsw_test_path: string;
  };
  model: {
    trained_local_artifact_available: boolean;
    artifact_path: string;
    error: string | null;
  };
  reports: {
    local_metrics_available: boolean;
    official_baseline_available: boolean;
    official_comparison_available: boolean;
    official_importance_available: boolean;
  };
  soc_store: {
    dataset_cases_count: number;
    cyber_lab_cases_count: number;
    case_states: string[];
  };
  active_uploads: number;
}

export interface PriorityBandInfo {
  code: "CRIT" | "HIGH" | "MED" | "LOW" | "INFO" | string;
  label: string;
  rank: number;
}

export interface FlowRow {
  row_index: number;
  flow_ref: string;
  proto: string | null;
  service: string | null;
  state: string | null;
  dur: number | null;
  sbytes: number | null;
  dbytes: number | null;
  spkts: number | null;
  dpkts: number | null;
  rate: number | null;
  AI_verdict: "Attack" | "Normal" | null;
  AI_attack_probability: number | null;
  priority_band: PriorityBandInfo;
  label: number | null;
  attack_cat: string | null;
  signal_score: number;
  signal_reasons: string[];
  flow_evidence: Record<string, unknown>;
}

export interface SocCaseSummary {
  case_id: number;
  flow_id: string;
  verdict: string;
  confidence: number | null;
  state: string;
  analyst_note: string;
  created_at: string;
  updated_at: string;
}

export interface SocCaseEvent {
  event_id: number;
  old_state: string | null;
  new_state: string;
  note: string;
  created_at: string;
}

export interface SocCaseDetailResponse {
  case: SocCaseSummary;
  flow_evidence: Record<string, unknown>;
  case_events: SocCaseEvent[];
  case_states: string[];
}

export interface DatasetOverviewResponse {
  provenance: {
    source_display: string;
    source_kind: string;
    rows_loaded: number;
    sample_size_limit: number;
    live_capture_enabled: boolean;
    has_original_ip_or_timestamp: boolean;
    predictions_available: boolean;
    model_error: string | null;
    notice: string;
  };
  kpis: {
    flows_read: number;
    ground_truth_attacks: number | null;
    ai_predicted_attacks: number | null;
    soc_cases_total: number;
  };
  priority_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    normal: number;
  } | null;
  protocol_distribution: Array<{ name: string; count: number }>;
  attack_category_distribution: Array<{ name: string; count: number }> | null;
  filter_options: {
    protocols: string[];
    services: string[];
    states: string[];
  };
  recent_cases: SocCaseSummary[];
}

export interface DatasetHuntingResponse {
  predictions_available: boolean;
  total_loaded: number;
  total_filtered: number;
  page: number;
  page_size: number;
  total_pages: number;
  rows: FlowRow[];
}

export interface DatasetEvaluationResponse {
  predictions_available: boolean;
  local_model_loaded: boolean;
  benchmark_metrics: {
    source_file: string;
    source_kind: string;
    train_size: number;
    test_size: number;
    attack_precision: number;
    attack_recall: number;
    attack_f1: number;
    average_precision_attack: number;
    confusion_matrix: { tn: number; fp: number; fn: number; tp: number };
  } | null;
  locked_threshold_comparison: {
    test_rows?: number;
    validation_selection_run_id?: number;
    evaluation_run_id?: number;
    delta_false_positive_candidate_minus_baseline?: number;
    delta_false_negative_candidate_minus_baseline?: number;
    baseline?: Record<string, number>;
    candidate?: Record<string, number>;
    error?: string;
  } | null;
  feature_importance: {
    source_kind: string;
    note: string;
    features: Array<{
      rank: number;
      feature: string;
      importance: number;
      importance_percent: number;
      encoded_dimensions: number;
    }>;
  } | null;
  sample_threshold_diagnostics: {
    status: "ok" | "counts_only" | "no_model" | "invalid_labels" | "not_available";
    message?: string;
    rows: Array<Record<string, number>>;
  };
}

export interface DatasetAlertsResponse {
  predictions_available: boolean;
  threshold: number;
  total_alerts: number;
  displayed_count?: number;
  priority_counts: { CRIT: number; HIGH: number; MED: number; LOW: number };
  alerts: FlowRow[];
  message?: string;
}

export interface ZeekEventRow {
  record_index: number;
  row_number: number;
  event_time_utc: string;
  uid: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: string;
  service: string | null;
  conn_state?: string | null;
  duration_s: number | null;
  orig_bytes: number | null;
  resp_bytes: number | null;
  orig_pkts: number | null;
  resp_pkts: number | null;
  origin: string;
  source_sha256: string;
}

export interface CyberLabParseResponse {
  filename: string;
  is_synthetic_demo: boolean;
  summary: {
    flow_count: number;
    unique_sources: number;
    unique_destinations: number;
    first_event_utc: string;
    last_event_utc: string;
    source_sha256: string;
    protocol_counts: Record<string, number>;
  };
  preview_count: number;
  events: ZeekEventRow[];
}

export interface CyberLabTraceCandidate {
  record_index: number;
  zeek_row: number;
  uid: string;
  attack_probability: number;
  priority_band: PriorityBandInfo;
  event_time_utc: string;
  src_ip: string;
  dst_ip: string;
  proto: string;
  selectable_for_case: boolean;
}

export interface CyberLabTraceResponse {
  source_sha256: string;
  trace_sha256: string;
  flow_count: number;
  candidate_count: number;
  selected_threshold: number;
  candidates: CyberLabTraceCandidate[];
}

export interface RedTeamScenario {
  scenario_id: string;
  title: string;
  objective: string;
  category: string;
}

export interface RedTeamStateResponse {
  session_id: string;
  execution_enabled: boolean;
  network_access: boolean;
  max_proposals: number;
  scenarios: RedTeamScenario[];
  audit: {
    proposals: number;
    manual_feedback_count: number;
    pending_proposal_id: number | null;
    execution_enabled: boolean;
    network_access: boolean;
    blue_team_outcomes_verified: boolean;
    events: Array<Record<string, unknown>>;
  };
  summary: {
    origin: string;
    total: number;
    scenarios: Array<{
      scenario_id: string;
      observations: number;
      unflagged: number;
      unflagged_fraction: number | null;
    }>;
  };
  pending_plan: {
    scenario_id: string;
    title: string;
    objective: string;
    strategy: string;
    rationale: string;
    feedback_count: number;
    execution_enabled: boolean;
    network_access: boolean;
    feedback_origin: string;
  } | null;
}

export interface RedTeamBenchmarkResponse {
  benchmark_version: number;
  origin: string;
  execution_enabled: boolean;
  network_access: boolean;
  rounds_per_trial: number;
  trials_per_strategy: number;
  seed: number;
  interpretation_warning: string;
  policies: Record<
    string,
    {
      mean_synthetic_unflagged_fraction: number;
      mean_expected_pseudo_regret: number;
      selection_counts: Record<string, number>;
    }
  >;
}

export interface NewLogVerifyResponse {
  review_token: string;
  flow_count: number;
  research_candidate_count: number;
  visible_flow_count: number;
  validation_threshold: number;
  manifest_sha256: string;
  report_sha256: string;
  declared_scope_sha256: string;
  pcap_verified: boolean;
  candidates: Array<{
    zeek_row: number;
    record_index: number;
    uid: string;
    attack_probability: number;
    priority_band: PriorityBandInfo;
    event_time_utc: string;
    src_ip: string;
    dst_ip: string;
  }>;
}

export interface PrivateZeekCaseItem {
  case_id: number;
  state: string;
  created_at: string;
  updated_at: string;
  zeek_uid: string | null;
  source_sha256: string | null;
}

export interface PrivateZeekCaseDetail {
  case: Record<string, unknown>;
  flow_evidence: Record<string, unknown>;
  case_events: Array<Record<string, unknown>>;
  history_truncated: boolean;
}
