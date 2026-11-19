/**
 * Actual Chromium regression for the local-only VMware JSONL viewer.
 * This exercises file-input rendering, strict provenance and partial-write behavior.
 * It does not run VMware, SSH, packets, model inference or a SOC workflow.
 */
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { chromium } from "playwright-core";

const url = "http://127.0.0.1:3000/vmware-progress";
const executablePath = [
  process.env.CHROME_BIN,
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
].find((path) => path && existsSync(path));

if (!executablePath) throw new Error("Chromium/Chrome executable required");

async function waitForServer() {
  for (let attempt = 0; attempt < 75; attempt += 1) {
    try {
      const result = await fetch(url, { signal: AbortSignal.timeout(1500) });
      if (result.ok) return;
    } catch { /* start retry */ }
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  throw new Error("Next.js did not start");
}

const base = {
  kind: "da005_vmware_stepwise_progress_v1",
  observed_at_utc: "2026-11-19T06:00:00+00:00",
  mode: "operator_assisted_benign_hostonly_experiment",
  stage_evidence: "program_execution_only_not_independently_verified",
  vmware_isolation_verified: false,
  attack_executed: false,
  ai_attack_planning_executed: false,
  operational_ai_detection_verified: false,
  soc_alerts_created: false,
};
const event = (seq, stage, status, counts) =>
  ({ ...base, seq, stage, status, ...(counts ? { counts } : {}) });
const entries = [
  event(1, "preflight", "completed"),
  event(2, "red", "running"),
  event(3, "red", "completed", { attempted_probes: 2 }),
  event(4, "zeek", "running"),
  event(5, "zeek", "completed", { snapshot_flow_count: 2 }),
  event(6, "blue", "skipped"),
  event(7, "audit", "running"),
  event(8, "audit", "completed", { candidate_matches: 1, unmatched_attempts: 1 }),
  event(9, "soc", "skipped"),
];
const terminal = {
  kind: "da005_vmware_stepwise_terminal_v1",
  status: "completed",
  result: {
    mode: "STEPWISE_VMWARE_BENIGN_CAPTURE",
    vmware_isolation_verified: false,
    attack_executed: false,
    operational_detection_verified: false,
    automated_soc_alerts: false,
    full_one_click_dual_ai: false,
  },
};

await waitForServer();
const browser = await chromium.launch({
  executablePath, headless: true, args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  let uploads = 0;
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("request", (request) => {
    if (request.method() === "POST" || request.method() === "PUT") uploads += 1;
  });
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await page.getByRole("heading", { name: "Quy trình kiểm thử từng giai đoạn" }).waitFor();
  await page.getByLabel("Mở tệp JSONL VMware").setInputFiles({
    name: "vmware-stage-progress.jsonl",
    mimeType: "application/x-ndjson",
    buffer: Buffer.from([...entries, terminal].map((x) => JSON.stringify(x)).join("\n") + "\n"),
  });
  const progress = page.locator('section[aria-labelledby="vmware-events"]');
  await progress.getByText(/9 sự kiện/).waitFor();
  assert.equal(await progress.locator("li").count(), 9);
  await page.getByText("Phần mềm kết thúc", { exact: true }).first().waitFor();
  assert.match(await page.locator("body").innerText(), /Flow trong snapshot/);
  assert.match(await page.locator("body").innerText(), /UID trùng khớp ứng viên/);
  assert.match(await page.locator("body").innerText(), /Chưa xác minh|chưa xác minh|CHƯA XÁC MINH/);
  assert.equal(uploads, 0, "JSONL must not be posted to any API");

  const forged = entries.map((x) => ({ ...x }));
  forged[0] = { ...forged[0], vmware_isolation_verified: true };
  await page.getByLabel("Mở tệp JSONL VMware").setInputFiles({
    name: "forged.jsonl", mimeType: "application/x-ndjson",
    buffer: Buffer.from(forged.map((x) => JSON.stringify(x)).join("\n") + "\n"),
  });
  await page.getByRole("alert").filter({ hasText: "Từ chối sự kiện tuyên bố" }).waitFor();
  assert.match(await progress.innerText(), /0 sự kiện/);
  assert.equal(uploads, 0);

  const partial = JSON.stringify(event(1, "preflight", "completed")) + "\n" + '{"kind":"unfinished';
  await page.getByLabel("Mở tệp JSONL VMware").setInputFiles({
    name: "partial.jsonl", mimeType: "application/x-ndjson",
    buffer: Buffer.from(partial),
  });
  await progress.getByText(/1 sự kiện/).waitFor();
  await page.getByText(/đang ghi dở/).waitFor();
  await page.getByRole("button", { name: "Đóng phiên" }).click();
  assert.match(await progress.innerText(), /0 sự kiện/);
  assert.equal(errors.length, 0, "Browser emitted uncaught errors: " + errors.join("; "));
  console.log("PASS: Chromium local JSONL viewer validates stages, rejects forged claims, handles partial lines, and never uploads evidence");
} finally {
  await browser.close();
}
