# Red Team AI — reproducible synthetic policy comparison (research sandbox)

This is a **non-executing**, deterministic software demonstration of UCB1 versus the existing seeded Random policy. It is **not** an adversarial-emulation experiment, Blue Team evaluation, or evidence of detecting real attacks. No packet capture, socket, VMware control, shell command, exploit or network target is used.

## Fixed synthetic assumptions

The immutable three-label catalog from `src/red_team_ai/scenario_policy.py` is used without changing its policy. Each label has a **hypothetical** probability that a synthetic Blue Team observation would be `unflagged`:

| Planning label | Assumed P(synthetic unflagged) |
| --- | ---: |
| `baseline_web` | 0.10 |
| `dns_variation` | 0.35 |
| `connection_shift` | 0.70 |

These numbers were chosen **for demonstration** and are not estimated from Zeek, UNSW-NB15, real Blue Team predictions or authorized lab tests. They must never be described as measured attack-success rates. The benchmark is not connected to the manually entered Red Team feedback in the UI.

## Fairness and repeatability

For every trial, round and scenario, the simulator generates one deterministic Bernoulli potential outcome using a seed. **Both** strategies receive the same potential-outcome table (common random numbers), but each policy sees only the selected scenario's feedback and updates from that observation. Different strategies can select different labels on the same round.

The report includes each strategy's mean synthetic unflagged fraction, mean **expected pseudo-regret** against the best *assumed* scenario probability, per-scenario selection counts and per-trial results. Expected pseudo-regret is the sum of `best_assumed_probability - selected_assumed_probability`; it is not observed incident loss, detection latency or a statistical confidence interval. This simulation compares policies under one hand-crafted environment, not robust real-world performance. Random uses the existing deterministic seed/round policy, not a cryptographically secure RNG.

Limits: 3–500 rounds per trial, 2–40 trials per strategy, integer seed 0–1,000,000. Both policy outputs must keep `execution_enabled=false` and `network_access=false`, otherwise the benchmark refuses to continue. Exported JSON includes `origin=synthetic_bernoulli_not_blue_team_evidence` and a prominent interpretation warning.

## Run

From the repository root on Windows:

~~~powershell
py -3.12 -m pytest -q tests/test_red_team_synthetic_benchmark.py
streamlit run app.py
~~~

Open **Red Team Lab** and use **So sánh UCB1 và Random trên dữ liệu TỔNG HỢP**. The comparison runs only when the operator presses the simulation button and may be downloaded as JSON. It does not save to the SOC database or alter Dataset Mode.

## Gate before genuine AI-vs-AI research

Real policy comparison requires (1) explicit authorized and isolated lab scope; (2) fixed non-destructive scenario protocol and effective stop controls before active replay; (3) independently recorded Blue Team predictions linked to original, source-hashed Zeek events; (4) a pre-registered reward definition and comparison budget; (5) multiple host/scenario sessions and untouched held-out data. None of those experimental observations is supplied by this simulator. Do not feed its outputs into Blue Team training, report its numbers as attack detection, or silently enable network execution.
