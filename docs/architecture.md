# AttackCastle Architecture

AttackCastle is implemented as a modular monolith:

- CLI input and profile configuration
- target classification and scope normalization
- adaptive workflow scheduling
- pluggable adapters for scan/enrichment stages
- normalized data model and findings engine
- HTML and JSON reporting outputs

Adaptive escalation path (profile/policy permitting):

`subdomain_enum -> dns -> check_websites/web_probe -> masscan/nmap -> web_discovery -> tls/service_exposure -> whatweb/nikto/nuclei/framework_checks/sqlmap -> wpscan -> cve_enricher -> findings -> report`

Core flow:

`target -> classify -> plan -> execute adapters -> normalize -> generate findings -> render report`

Lifecycle state machine:

`created -> planned -> running -> completed|failed|cancelled`

Planner characteristics:

- capability-based tasks
- declarative rules loaded from `orchestration/rules/default_rules.yaml`
- profile noise policy checks
- explainable plan artifacts with deferred/skipped reasons

Run durability:

- per-task checkpoints in `checkpoints/`
- run lock file at `locks/.run.lock`
- run manifest hashing at `data/run_manifest.json`

Design priorities:

- safe defaults for authorized testing
- clear module boundaries
- partial-result tolerance
- easy adapter/template extension
