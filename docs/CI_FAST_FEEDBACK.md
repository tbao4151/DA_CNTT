# DA005 — Faster GitHub Actions feedback without suppressing main evidence

Six frequently triggered checks use workflow-level concurrency grouping by workflow name, GitHub event type and branch/PR identity. A fresh feature branch push cancels obsolete runs from that **same workflow/event/branch**; a new PR revision cancels obsolete jobs from that **same workflow/PR**. Push and PR jobs have separate groups to avoid cancelling a required PR check merely because its branch-push counterpart started later.

The cancellation condition explicitly excludes `refs/heads/main` and `workflow_dispatch`. These remain reviewable as independent full runs, even if multiple are queued, so release and operator-triggered audit evidence is preserved.

Touched workflows: Mini-SIEM CI, Windows offline Zeek, cooperative STOP matrix, SHA-pinned VMware JSONL audit matrix, Python → Chromium cross-stack acceptance, and Next.js frontend gates. No test is removed, skipped, shortened, or weakened; Python/Node versions, matrix OS targets and test commands are unchanged.

This reduces repeated work during rapid feature pushes, not the runtime of the final comprehensive test run. A cancelled older feature run must never be reported as a pass; only a success on the PR's **exact latest head SHA** counts toward merging. This does not start, alter or cancel ChatGPT development automations and has no effect on VMware experiments.
