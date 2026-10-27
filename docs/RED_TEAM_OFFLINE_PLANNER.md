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
