# DA005 — Python UCB1 → private receipt + JSONL → Chromium acceptance

This cross-stack test combines the REAL Python operator profile v2 loader, SHA-256 verification, UCB1 chooser, exclusive private .red-plan.json writer, stepwise dry-run JSONL writer and production Next.js /vmware-progress browser.

The fixture is created by tests/emit_vmware_red_plan_browser_case.py in a private CI runner temp folder outside Git. Its mock profile uses three human-entered feedback samples. UCB1 deterministically chooses dns_variation; the same approved catalog ID must occur in the profile. The CLI runs with execution OFF (no --execute). The test patches packet probes, SSH/SCP and Blue bridge to raise if called. Therefore ALL CI artifacts are intentionally synthetic; no physical VMware network state, Zeek source, model or SOC alert is measured.

The browser test frontend/scripts/vmware-python-browser-e2e.mjs imports both:
- python_ucb1.jsonl — actual CLI dry-run and terminal
- python_ucb1.red-plan.json — actual Python receipt linked by filename and user-supplied profile SHA

It asserts that the screen shows UCB1 and the selected fixed benign DNS scenario, displays the limited manual-feedback provenance, denies forged attack_executed=true, clears the plan on a different JSONL session, and never sends HTTP POST/PUT/PATCH/DELETE.

The test does NOT independently verify the original profile digest in Chromium, nor prove the selected scenario was actually sent onto the network. When writing a scientific report, do not include this CI test as physical Host-only attack/detection evidence. Real evidence must come from separately controlled and observed VMware + Zeek experiments with independent labels and model validation.

GitHub Actions workflow: .github/workflows/vmware-jsonl-cross-stack.yml. Its private test files are not saved to the repository or published as results.
