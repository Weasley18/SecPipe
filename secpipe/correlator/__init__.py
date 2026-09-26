"""Log correlation: multi-source, stateful detection rules that LogQL alone
cannot express (brute force then success, request-then-shell chains, token
reuse across IPs). Runs as a Kubernetes CronJob every minute."""
