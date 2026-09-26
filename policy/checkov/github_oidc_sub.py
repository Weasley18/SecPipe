"""CKV_SECPIPE_2: GitHub OIDC trust policies must pin exact ``sub`` claims.

Checkov's CKV_AWS_358 only inspects statements whose principal is a literal
``oidc-provider/token.actions.githubusercontent.com`` ARN (a reference such as
``aws_iam_openid_connect_provider.github.arn`` is invisible to it) and it
accepts ``repo:owner/*``. This check keys off the condition variable instead
and rejects any wildcard, so every trust policy federated with GitHub must
name the repository and the branch, environment or event exactly.
"""

from __future__ import annotations

import re
from typing import Any

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.common.util.type_forcers import force_list
from checkov.terraform.checks.data.base_check import BaseDataCheck

OIDC_HOST = "token.actions.githubusercontent.com"
SUB_VARIABLE = re.compile(r"^token\.actions\.githubusercontent\.com(?:/[A-Za-z0-9_-]+)?:sub$")
# repo:<owner>/<repo>:<context>, context = ref:refs/..., environment:<name> or pull_request
# Checkov leaves references it cannot resolve as text, e.g. "var.allowed_subjects".
UNRESOLVED = re.compile(r"\$\{|^(var|local|module|data)\.")
EXACT_SUBJECT = re.compile(
    r"^repo:[A-Za-z0-9-]+/[A-Za-z0-9._-]+:(ref:refs/(heads|tags)/[^*?]+|environment:[^*?]+|pull_request)$"
)


def _first(value: Any) -> Any:
    while isinstance(value, list) and len(value) == 1:
        value = value[0]
    return value


def _strings(value: Any) -> list[str]:
    out: list[str] = []
    for item in force_list(value):
        if isinstance(item, list):
            out.extend(_strings(item))
        elif item is not None:
            out.append(str(item))
    return out


class GitHubOIDCExactSubject(BaseDataCheck):  # type: ignore[misc]
    def __init__(self) -> None:
        super().__init__(
            name="Ensure GitHub Actions OIDC trust policies pin exact sub claims (no wildcards)",
            id="CKV_SECPIPE_2",
            categories=[CheckCategories.IAM],
            supported_data=["aws_iam_policy_document"],
            guideline="https://github.com/Weasley18/SecPipe/blob/main/policy/checkov/README.md#ckv_secpipe_2",
        )

    def scan_data_conf(self, conf: dict[str, list[Any]]) -> CheckResult:
        saw_github = False
        for statement in force_list(conf.get("statement")):
            if not isinstance(statement, dict):
                continue
            conditions = [c for c in force_list(statement.get("condition")) if isinstance(c, dict)]
            actions = _strings(statement.get("actions"))
            github = any(OIDC_HOST in v for c in conditions for v in _strings(c.get("variable")))
            if not github and "sts:AssumeRoleWithWebIdentity" not in actions:
                continue
            if not github:
                # Web identity with no GitHub condition at all: only fail when the
                # federated principal is visibly GitHub's provider.
                principals = [p for p in force_list(statement.get("principals")) if isinstance(p, dict)]
                if not any(OIDC_HOST in v for p in principals for v in _strings(p.get("identifiers"))):
                    continue
            saw_github = True
            subjects = [
                (str(_first(c.get("test"))), _strings(c.get("values")))
                for c in conditions
                if any(SUB_VARIABLE.match(v) for v in _strings(c.get("variable")))
            ]
            if not subjects:
                return CheckResult.FAILED  # audience only: any repository on GitHub can assume the role
            for test, values in subjects:
                if test not in {"StringEquals", "ForAnyValue:StringEquals"}:
                    return CheckResult.FAILED
                for value in values:
                    if "*" in value or "?" in value:
                        return CheckResult.FAILED
                    if UNRESOLVED.search(value):
                        continue  # the module's variable validation rejects wildcards at plan time
                    if not EXACT_SUBJECT.match(value):
                        return CheckResult.FAILED
        return CheckResult.PASSED if saw_github else CheckResult.UNKNOWN

    def get_evaluated_keys(self) -> list[str]:
        return ["statement/[0]/condition", "statement/[0]/principals"]


check = GitHubOIDCExactSubject()
