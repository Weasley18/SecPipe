# 0005: Loki + Alloy instead of ELK

- **Status:** accepted

## Context
The runtime layer needs app auth logs, ingress access logs, Falco events and
the API audit log in one queryable place, on a laptop-sized kind cluster that
also runs Prometheus, Grafana and Falco.

## Decision
Grafana Loki (single binary, filesystem storage) with Grafana Alloy shipping
logs. Loki indexes labels, not content, so it runs in a few hundred MB, and
Grafana shows logs next to the Prometheus metrics on the same dashboard.

## Consequences
- LogQL is less powerful for ad-hoc search than Elasticsearch; the stateful,
  multi-source detections therefore live in the Python correlator, which only
  changes its query client to move to ELK/OpenSearch or Splunk.
- Labels (`namespace`, `app`, `pod`) are the contract between Alloy, the
  correlator's queries and the dashboard; they are defined in one place
  (`monitoring/alloy/config.alloy`).
