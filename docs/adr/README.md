# Architecture decision records

Short records of the decisions that shape SecPipe: context, decision,
consequences. Superseded records stay, marked as such.

| # | Decision |
| --- | --- |
| [0001](0001-semgrep-and-bandit.md) | Run Semgrep and Bandit, not one SAST tool |
| [0002](0002-policy-as-code.md) | The gate's rules live in `policy.yaml`, not in scanner flags |
| [0003](0003-keyless-cosign.md) | Keyless Cosign signing instead of a key pair |
| [0004](0004-kyverno-over-gatekeeper.md) | Kyverno instead of OPA Gatekeeper for admission |
| [0005](0005-loki-over-elk.md) | Loki + Alloy instead of ELK for the log stack |
| [0006](0006-fail-closed.md) | Fail closed when a scanner produces no usable report |
| [0007](0007-aws-profile-cost-tradeoffs.md) | Cost-driven trade-offs in the AWS profile and the kind cluster |
