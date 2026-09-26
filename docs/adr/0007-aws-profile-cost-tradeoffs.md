# 0007: Cost-driven trade-offs in the AWS profile and the kind cluster

- **Status:** accepted

## Context
The AWS profile must demonstrate cloud hardening while staying near free, and
the cluster must run on a laptop and in a GitHub runner.

## Decision
- **No EKS, no NAT gateway**: both bill by the hour; the cluster stays on kind.
- **Three customer-managed KMS keys** (state, reports, ECR, about 1 USD/month
  each) because state and reports can hold sensitive data; the budget alarm
  defaults to 10 USD/month.
- **No S3 server-access logging or cross-region replication** on the reports
  and state buckets (`CKV_AWS_18`, `CKV_AWS_144`, `CKV2_AWS_62`, Trivy
  `AWS-0089`), each skipped inline with this justification. Upgrade path:
  CloudTrail S3 data events to an org trail.
- **Postgres in a StatefulSet** for the demo; production would use a managed
  database with backups, TLS and IAM authentication.
- **kind node image pinned to Kubernetes 1.35** because the `tehcyx/kind`
  provider (0.11.0) embeds kind v0.31, which cannot bootstrap the 1.37 image.
- **Ingress: Traefik.** ingress-nginx was retired in March 2026; the manifests
  use a plain `Ingress` with `ingressClassName: traefik`.

## Consequences
- Checkov and Trivy stay green on `main` with a small, justified set of skips
  that the suppression inventory counts and shows.
- Anyone forking this into a real account should revisit the logging items first.
