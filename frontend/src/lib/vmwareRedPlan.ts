/**
 * Strict local-only viewer contract for one signed-off *planning* label.
 *
 * This reads a v2 profile's private .red-plan.json receipt. It DOES NOT
 * authenticate the profile hash, VM isolation, network execution, Blue model
 * inference or SOC activity. It never makes requests or opens URLs.
 */
export const MAX_VMWARE_RED_PLAN_BYTES = 4096;

export type VMwareRedPlan = {
  kind: "da005_operator_approved_red_policy_v1";
  profile_sha256: string;
  strategy: "ucb1" | "random";
  seed: number;
  selected_scenario_id: "baseline_web" | "dns_variation" | "connection_shift";
  feedback_count: number;
  feedback_origin: "operator_entered_unverified";
  policy_reproducible_from_pinned_profile: true;
  planning_only: true;
  attack_executed: false;
  verified_ai_detection: false;
  soc_alerts_created: false;
};

const REQUIRED_KEYS = [
  "kind", "profile_sha256", "strategy", "seed",
  "selected_scenario_id", "feedback_count", "feedback_origin",
  "policy_reproducible_from_pinned_profile", "planning_only",
  "attack_executed", "verified_ai_detection", "soc_alerts_created",
] as const;

export const RED_SCENARIO_LABELS: Record<VMwareRedPlan["selected_scenario_id"], string> = {
  baseline_web: "HTTP HEAD (dịch vụ lab TCP/8080)",
  dns_variation: "DNS .invalid (UDP/53)",
  connection_shift: "TCP connect/close (SSH TCP/22, không xác thực)",
};

export function expectedRedPlanFilename(progressName: string): string {
  if (!/^[a-zA-Z0-9_.-]+\.jsonl$/.test(progressName)) {
    throw new Error("Tên tệp tiến độ không hợp lệ để ghép biên nhận Red.");
  }
  return progressName.slice(0, -".jsonl".length) + ".red-plan.json";
}

export function parseVmwareRedPlan(text: string): VMwareRedPlan {
  if (
    typeof text !== "string" || text.length === 0 ||
    new TextEncoder().encode(text).length > MAX_VMWARE_RED_PLAN_BYTES ||
    text.charCodeAt(0) === 0xfeff
  ) {
    throw new Error("Biên nhận Red trống, vượt 4 KiB hoặc có BOM.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Biên nhận Red không phải JSON hợp lệ.");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Biên nhận Red phải là đối tượng JSON.");
  }
  const value = parsed as Record<string, unknown>;

  // The schema is deliberately flat and all legitimate string values are
  // token-like. Reject duplicate/escaped/unknown source property names
  // instead of silently accepting JSON.parse's last-key-wins behavior.
  const sourceKeys = [...text.matchAll(/"([a-z_]+)"\s*:/g)].map((m) => m[1]);
  if (
    sourceKeys.length !== REQUIRED_KEYS.length ||
    new Set(sourceKeys).size !== REQUIRED_KEYS.length ||
    !sourceKeys.every((key) => (REQUIRED_KEYS as readonly string[]).includes(key)) ||
    Object.keys(value).length !== REQUIRED_KEYS.length ||
    !REQUIRED_KEYS.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  ) {
    throw new Error("Biên nhận Red chứa thuộc tính trùng, sai hoặc không được phép.");
  }
  if (
    value.kind !== "da005_operator_approved_red_policy_v1" ||
    typeof value.profile_sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(value.profile_sha256) ||
    (value.strategy !== "ucb1" && value.strategy !== "random") ||
    typeof value.seed !== "number" || !Number.isSafeInteger(value.seed) ||
    value.seed < 0 || value.seed > 1_000_000 ||
    typeof value.selected_scenario_id !== "string" ||
    !Object.prototype.hasOwnProperty.call(RED_SCENARIO_LABELS, value.selected_scenario_id) ||
    typeof value.feedback_count !== "number" ||
    !Number.isSafeInteger(value.feedback_count) ||
    value.feedback_count < 0 || value.feedback_count > 128 ||
    value.feedback_origin !== "operator_entered_unverified" ||
    value.policy_reproducible_from_pinned_profile !== true ||
    value.planning_only !== true ||
    value.attack_executed !== false ||
    value.verified_ai_detection !== false ||
    value.soc_alerts_created !== false
  ) {
    throw new Error("Biên nhận Red sai provenance, kịch bản, bộ đếm hoặc tự nhận đã tấn công.");
  }
  return value as VMwareRedPlan;
}
