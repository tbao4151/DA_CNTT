/**
 * Real Chromium smoke for Step-by-Step SYNTHETIC REPLAY UX.
 * Backend is mocked intentionally: this test verifies browser rendering and
 * refusal to imply any operational VM/detection evidence, not live VMware.
 */
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { chromium } from "playwright-core";

const appUrl = "http://127.0.0.1:3000/automated-lab";
const executables = [
  process.env.CHROME_BIN,
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
].filter(Boolean);
const executablePath = executables.find((path) => existsSync(path));
if (!executablePath) {
  throw new Error("Real Chromium/Chrome is required for browser smoke");
}

async function waitForServer() {
  for (let attempt = 0; attempt < 75; attempt += 1) {
    try {
      const response = await fetch(appUrl, { signal: AbortSignal.timeout(1500) });
      if (response.ok) return;
    } catch { /* Next.js can be starting. */ }
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
  throw new Error("Next.js production server did not become ready");
}

const base = {
  session_id: "synthetic-browser-smoke-001",
  status: "completed",
  mode: "synthetic_replay",
  strategy: "ucb1",
  rounds: 2,
  current_round: 2,
  started_at: "2026-11-19T05:30:00Z",
  finished_at: "2026-11-19T05:30:10Z",
  event_count: 4,
  provenance: {
    source: "hardcoded_synthetic_zeek_fixture",
    network_execution: false,
    vmware_connected: false,
    ai_detection_executed: false,
    verified_attack_events: 0,
    verified_ai_alerts: 0,
    fixture_flows_per_round: 2,
  },
  events: [
    { seq: 1, time: "2026-11-19T05:30:01Z", stage: "red",
      message: "Red fixture decision", details: { round: 1, scenario_id: "baseline_web",
        scenario_title: "Benign synthetic label", rationale: "No network execution" }, source: "synthetic_replay" },
    { seq: 2, time: "2026-11-19T05:30:02Z", stage: "zeek",
      message: "Zeek synthetic fixture flows", details: { round: 1, sample_flow_count: 2 }, source: "synthetic_replay" },
    { seq: 3, time: "2026-11-19T05:30:03Z", stage: "blue",
      message: "Blue research inference OFF", details: { round: 1 }, source: "synthetic_replay" },
    { seq: 4, time: "2026-11-19T05:30:04Z", stage: "soc",
      message: "SOC synthetic audit only", details: { round: 1 }, source: "synthetic_replay" },
  ],
};
const report = {
  ...base,
  report_kind: "synthetic_replay_telemetry_only",
  verified_detection_metrics: null,
  real_network_flows: 0,
  verified_ai_alerts: 0,
  limitations: ["Browser smoke only. No VMware or operational attack detections."],
};

await waitForServer();
const browser = await chromium.launch({
  executablePath,
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
try {
  const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  let createCalls = 0;
  await page.route("**/api/v1/live-sessions**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const headers = {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "POST, GET, OPTIONS",
      "access-control-allow-headers": "Content-Type",
    };
    if (request.method() === "OPTIONS") {
      await route.fulfill({ status: 204, headers, body: "" });
      return;
    }
    if (path.endsWith("/live-sessions") && request.method() === "POST") {
      const requestBody = request.postDataJSON();
      assert.equal(requestBody.mode, "synthetic_replay");
      assert.equal(requestBody.rounds, 2);
      createCalls += 1;
      await route.fulfill({ status: 200, headers, body: JSON.stringify(base) });
      return;
    }
    if (path.endsWith("/report") && request.method() === "GET") {
      await route.fulfill({ status: 200, headers, body: JSON.stringify(report) });
      return;
    }
    await route.fulfill({ status: 404, headers, body: JSON.stringify({ detail: "Not mocked" }) });
  });

  await page.goto(appUrl, { waitUntil: "domcontentloaded" });
  const panel = page.locator('section[aria-labelledby="stepwise-title"]');
  await panel.waitFor({ state: "visible" });
  const group = panel.getByRole("group", { name: "Chọn giai đoạn để xem sự kiện" });
  assert.match(await panel.textContent(), /SYNTHETIC REPLAY/);
  assert.match(await panel.textContent(), /Chưa có sự kiện cho giai đoạn này/);
  await group.getByRole("button", { name: /Zeek · Synthetic Replay/ }).click();
  assert.match(await panel.textContent(), /Chưa có sự kiện cho giai đoạn này/);
  await page.getByRole("button", { name: "Bắt đầu replay tự động" }).click();
  try {
    await panel.getByText("Zeek synthetic fixture flows", { exact: true }).waitFor({ state: "visible", timeout: 12000 });
  } catch (error) {
    console.error("DIAGNOSTIC createCalls=", createCalls);
    console.error("DIAGNOSTIC alerts=", await page.locator('[role="alert"]').allTextContents());
    console.error("DIAGNOSTIC selected panel=", (await panel.innerText()).slice(0, 1800));
    console.error("DIAGNOSTIC body=", (await page.locator("body").innerText()).slice(0, 1800));
    console.error("DIAGNOSTIC page errors=", errors);
    throw error;
  }
  assert.equal(createCalls, 1);
  const cases = [
    [/Red Team · Planner/, "Red fixture decision"],
    [/Zeek · Synthetic Replay/, "Zeek synthetic fixture flows"],
    [/Blue Team · Inference OFF/, "Blue research inference OFF"],
    [/SOC · Audit Trail/, "SOC synthetic audit only"],
  ];
  for (const [label, message] of cases) {
    const button = group.getByRole("button", { name: label });
    await button.click();
    assert.equal(await button.getAttribute("aria-pressed"), "true");
    await panel.getByText(message, { exact: true }).waitFor({ state: "visible" });
    assert.match(await panel.textContent(), /Nguồn: SYNTHETIC REPLAY/);
  }
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Xuất báo cáo JSON" }).click(),
  ]);
  assert.match(download.suggestedFilename(), /^DA005_synthetic_replay_.*\.json$/);
  const saved = await download.path();
  assert.ok(saved, "Browser report download is required");
  const payload = JSON.parse(await readFile(saved, "utf8"));
  assert.equal(payload.report_kind, "synthetic_replay_telemetry_only");
  assert.equal(payload.provenance.vmware_connected, false);
  assert.equal(payload.verified_ai_alerts, 0);
  assert.equal(errors.length, 0, "Browser page must not emit uncaught errors: " + errors.join("; "));
  console.log("PASS: real Chromium Step-by-Step event filters and provenance-safe JSON download (mock API, not VMware)");
} finally {
  await browser.close();
}
