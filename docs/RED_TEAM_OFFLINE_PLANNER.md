# Red Team AI — offline scenario planner (research preview)

`src/red_team_ai/scenario_policy.py` and `pages/2_Red_Team_Lab.py` are the first independent Red Team module and UI. The catalog consists of three immutable **planning labels** (ordinary web-flow baseline, DNS variation, connection-pattern shift). No entry contains an attack command, network target, exploit, PCAP player, shell invocation or VMware control. Nothing is executed. The UI uses only Streamlit session state, so restarting the session loses manual feedback.

## Model and baseline

`choose_scenario(feedback, strategy="ucb1")` implements deterministic UCB1 over **operator-entered** binary observations. A value `blue_flagged=False` receives an exploration reward of 1; `True` receives 0. Untried scenarios are chosen first. `strategy="random"` is a seeded random baseline, not a second attack implementation. The selector outputs an offline JSON **proposal**, with `execution_enabled=false` and `network_access=false`. Neither algorithm demonstrates learning from a genuine Blue Team or any detection performance until independent observations and an experimental protocol exist.

Feedback is strictly bounded (10,000 rows), rejects extra keys/unknown scenarios and does not accept IP addresses, commands or payload fields. The UI never sends network traffic, runs subprocesses, reads VMware state or saves private observations to disk. The **Dừng phiên** button clears local planning state; it is **not** a kill switch for real traffic, since no real traffic process exists.

## Run and test

From the repository root, install `requirements-app.txt`, run `streamlit run app.py`, and open **Red Team Lab** from the Streamlit navigation. The existing Dataset Mode and Cyber Lab pages remain separate. On Windows:

```powershell
py -3.12 -m pytest -q tests/test_red_team_scenario_policy.py
```

Tests use synthetic operator feedback and a Streamlit empty-state smoke check. They cannot establish genuine attack detection, safe isolation, host-level generalization or UI behavior on a student laptop.

## Next safety and research gates

Before adding *any* replay/execution: obtain documented student authorization, verify VMware Host-only isolation, implement operator opt-in, lab allowlist, bounded rates, audit logging and an effective emergency stop. Attach only owned/authorized offline fixtures and distinguish synthetic replay from captured data. Evaluate UCB1 versus random with a preregistered protocol and independently verified Blue Team outcomes; never call manually entered feedback ground truth. No active Red Team behavior is authorized by this preview.


## In-memory proposal-to-feedback timeline (29/10/2026)

The Red Team page now keeps a bounded, session-only `red_team_audit_events` timeline. Each proposed catalog scenario records a sequential proposal ID, exact policy (`ucb1` or `random`), random seed and UI-action UTC timestamp. A subsequent **operator-entered** `blue_flagged` observation must reference that same outstanding proposal ID; the UI does not accept arbitrary scenario feedback or a second proposal while the first is pending. The module replays policy selection from prior linked feedback and rejects mismatched selections, duplicate/unlinked observations, unknown keys, non-boolean feedback, out-of-order timestamps and any assertion of network execution or verified outcomes. It caps the session at 1,000 proposals.

The UI shows a chronological table and offers a JSON export. **The timestamps record button actions, not network events or detection times.** JSON is editable, unsigned and not authenticated scientific evidence. An observation is always `verified=false`, even if an operator types that Blue Team flagged something. Neither a proposed scenario nor its feedback establishes that traffic was generated or that Blue Team actually detected an attack. The planner remains offline and never runs a replay. The stop button clears the session-only audit and synthetic comparison; no real traffic process exists to stop.

On Windows Python 3.12.9 run:

```powershell
py -3.12 -m pytest -q tests/test_red_team_planning_audit.py tests/test_red_team_scenario_policy.py
```

To check the actual UI, run `streamlit run app.py`, navigate to **Red Team Lab**, propose one offline scenario, record an explicitly unverified observation, review the timeline, export JSON and clear the session. Keep the exported planning notes private. For a future scientific UCB1/random comparison, separately establish authorized lab observations, a predefined protocol, independent Blue Team outcomes and time measurements; this session log is not that evidence.
