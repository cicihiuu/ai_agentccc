from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


MAX_SAMPLES_PER_RULE = 2

GLOBAL_PATH_DENY_MARKERS = (
    "node_modules/",
    "vendor/",
    ".git/objects/",
    ".dist-info/",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
)
GLOBAL_PATH_DENY_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".exe",
    ".dll",
    ".so",
    ".bin",
)


@dataclass(frozen=True, slots=True)
class SecretRule:
    id: str
    title: str
    severity: str
    category: str
    regex: Pattern[str]
    keywords: tuple[str, ...]
    path_allow: tuple[str, ...]
    path_deny: tuple[str, ...]
    recommendation: str
    consumers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SecretMatch:
    rule_id: str
    title: str
    severity: str
    category: str
    recommendation: str
    consumers: tuple[str, ...]
    source_label: str
    location: str
    sample: str
    match_count: int


def _compile(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        id="private-key-block",
        title="Private key material recovered from backup",
        severity="critical",
        category="secret_material",
        regex=_compile(r"-----BEGIN (?:(?:RSA|EC|OPENSSH|DSA) PRIVATE KEY|PRIVATE KEY)-----", re.IGNORECASE),
        keywords=("private key", "begin", "openssh"),
        path_allow=(),
        path_deny=(),
        recommendation="Rotate the exposed private key material immediately and remove it from any downloadable backup artifacts.",
        consumers=("orchestrator", "poc"),
    ),
    SecretRule(
        id="env-secret-assignment",
        title="Exposed environment-style secret assignment recovered from backup",
        severity="high",
        category="secret_material",
        regex=_compile(
            r"""(?im)^(?:export\s+)?(?:[A-Z][A-Z0-9_]{1,63}|(?:db|mysql|redis|api|app|secret|token|password|passwd|pwd)[A-Za-z0-9_]*)\s*=\s*['"]?[^'"\s#]{6,}"""
        ),
        keywords=("db_", "mysql_", "redis_", "api_", "secret", "token", "password", "app_key", "access_key"),
        path_allow=(),
        path_deny=(),
        recommendation="Rotate exposed environment secrets and move secret-bearing files outside web-accessible backups.",
        consumers=("orchestrator", "sql", "js", "poc"),
    ),
    SecretRule(
        id="plaintext-password",
        title="Hardcoded password or credential in recovered files",
        severity="high",
        category="secret_material",
        regex=_compile(r"""(?im)\b(?:password|passwd|pwd|db_password|db_pass)\b\s*[:=]\s*['"]?[^'"\s#]{3,}"""),
        keywords=("password", "passwd", "pwd", "db_password"),
        path_allow=(),
        path_deny=(),
        recommendation="Remove hardcoded credentials from source and rotate the exposed accounts.",
        consumers=("orchestrator", "sql", "js", "poc"),
    ),
    SecretRule(
        id="database-dsn-credential",
        title="Database connection credential recovered from backup",
        severity="high",
        category="database_config",
        regex=_compile(
            r"""(?i)\b(?:mysql|postgres(?:ql)?|mariadb|mssql|redis)://[^/\s:@'"]{1,80}:[^/\s@'"]{1,80}@[^/\s'"]{1,160}"""
        ),
        keywords=("mysql://", "postgres://", "postgresql://", "redis://", "mariadb://", "database_url", "jdbc:"),
        path_allow=(),
        path_deny=(),
        recommendation="Review database connection handling and rotate any credentials exposed through downloadable backups.",
        consumers=("orchestrator", "sql", "poc"),
    ),
    SecretRule(
        id="aws-access-key-id",
        title="AWS access key ID recovered from backup",
        severity="high",
        category="secret_material",
        regex=_compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
        keywords=("akia", "asia", "abia", "acca", "a3t"),
        path_allow=(),
        path_deny=(),
        recommendation="Rotate exposed AWS access keys and remove them from recoverable backups.",
        consumers=("orchestrator", "poc"),
    ),
    SecretRule(
        id="aws-secret-access-key",
        title="AWS secret access key recovered from backup",
        severity="high",
        category="secret_material",
        regex=_compile(r"""(?im)\baws_secret_access_key\b\s*[:=]\s*['"]?([A-Za-z0-9/+=]{20,})"""),
        keywords=("aws_secret_access_key",),
        path_allow=(),
        path_deny=(),
        recommendation="Rotate exposed AWS secret keys and remove them from recoverable backups.",
        consumers=("orchestrator", "poc"),
    ),
    SecretRule(
        id="gcp-service-account-json",
        title="GCP service account credential recovered from backup",
        severity="high",
        category="secret_material",
        regex=_compile(
            r'(?is)"type"\s*:\s*"service_account".{0,500}"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----'
        ),
        keywords=("service_account", "private_key", "client_email"),
        path_allow=(".json", "credentials.json", "service-account"),
        path_deny=(),
        recommendation="Remove service account JSON files from exposed backups and rotate the embedded cloud credentials.",
        consumers=("orchestrator", "poc"),
    ),
    SecretRule(
        id="kube-client-material",
        title="Kubernetes client token or certificate material recovered from backup",
        severity="high",
        category="secret_material",
        regex=_compile(
            r"""(?im)\b(?:token|certificate-authority-data|client-certificate-data|client-key-data)\b\s*:\s*['"]?[A-Za-z0-9+/=._-]{16,}"""
        ),
        keywords=("certificate-authority-data", "client-certificate-data", "client-key-data", "token:"),
        path_allow=(".kube/config", "kubeconfig", ".yaml", ".yml"),
        path_deny=(),
        recommendation="Rotate exposed Kubernetes access material and remove kubeconfig backups from public access.",
        consumers=("orchestrator", "poc"),
    ),
    SecretRule(
        id="github-token",
        title="GitHub token recovered from backup",
        severity="high",
        category="secret_material",
        regex=_compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b"),
        keywords=("ghp_", "github_pat_"),
        path_allow=(),
        path_deny=(),
        recommendation="Rotate exposed GitHub tokens and remove them from recoverable backups.",
        consumers=("orchestrator", "poc"),
    ),
    SecretRule(
        id="gitlab-token",
        title="GitLab personal access token recovered from backup",
        severity="high",
        category="secret_material",
        regex=_compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
        keywords=("glpat-",),
        path_allow=(),
        path_deny=(),
        recommendation="Rotate exposed GitLab tokens and remove them from recoverable backups.",
        consumers=("orchestrator", "poc"),
    ),
    SecretRule(
        id="openai-anthropic-key",
        title="LLM provider API key recovered from backup",
        severity="high",
        category="secret_material",
        regex=_compile(r"\b(?:sk-proj-[A-Za-z0-9_-]{20,}|sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,})\b"),
        keywords=("sk-proj-", "sk-ant-", "openai", "anthropic", "api_key"),
        path_allow=(),
        path_deny=(),
        recommendation="Rotate exposed API keys and remove them from recoverable backups.",
        consumers=("orchestrator", "poc"),
    ),
    SecretRule(
        id="slack-token-webhook",
        title="Slack token or webhook recovered from backup",
        severity="high",
        category="secret_material",
        regex=_compile(r"\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,})\b"),
        keywords=("xox", "hooks.slack.com/services"),
        path_allow=(),
        path_deny=(),
        recommendation="Rotate exposed Slack credentials and remove them from recoverable backups.",
        consumers=("orchestrator", "poc"),
    ),
    SecretRule(
        id="htpasswd-hash",
        title="Htpasswd credential file recovered from backup",
        severity="high",
        category="secret_material",
        regex=_compile(r"(?m)^[^:\n]{1,80}:\$?(?:2[aby]|apr1|1|5|6)\$[^\n]+$"),
        keywords=("$apr1$", "$2y$", "$2a$", "$2b$", "$6$"),
        path_allow=(".htpasswd", "htpasswd"),
        path_deny=(),
        recommendation="Treat exposed htpasswd files as credential disclosure and rotate affected accounts.",
        consumers=("orchestrator", "poc"),
    ),
    SecretRule(
        id="framework-signing-key",
        title="Framework application signing secret recovered from backup",
        severity="high",
        category="app_config",
        regex=_compile(
            r"""(?im)\b(?:APP_KEY|SECRET_KEY|DJANGO_SECRET_KEY|jwt_secret(?:_key)?|rails_master_key|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)\b(?:[^=\n:]{0,40})[:=]?\s*['"(]*[A-Za-z0-9+/=:_-]{8,}"""
        ),
        keywords=("app_key", "secret_key", "jwt_secret", "auth_key", "secure_auth_key", "nonce_salt"),
        path_allow=(),
        path_deny=(),
        recommendation="Rotate exposed framework secrets and remove source or config backups from public access.",
        consumers=("orchestrator", "sql", "js", "poc"),
    ),
)


def is_denied_path(source_label: str) -> bool:
    lowered = source_label.replace("\\", "/").lower()
    if any(marker in lowered for marker in GLOBAL_PATH_DENY_MARKERS):
        return True
    return lowered.endswith(GLOBAL_PATH_DENY_SUFFIXES)


def _path_allowed(rule: SecretRule, lowered_path: str) -> bool:
    if rule.path_allow and not any(marker.lower() in lowered_path for marker in rule.path_allow):
        return False
    if any(marker.lower() in lowered_path for marker in rule.path_deny):
        return False
    return True


def _keyword_match(rule: SecretRule, lowered_text: str) -> bool:
    if not rule.keywords:
        return True
    return any(keyword.lower() in lowered_text for keyword in rule.keywords)


def _compact_sample(value: str) -> str:
    return " ".join(value.split())[:180]


def mask_secret_sample(rule_id: str, raw: str) -> str:
    compact = _compact_sample(raw)
    if not compact:
        return f"masked({rule_id}:empty)"
    if "BEGIN " in compact and "PRIVATE KEY" in compact:
        return f"masked({rule_id}:private-key-block)"
    if compact.startswith("https://hooks.slack.com/services/"):
        return "masked(slack-webhook:https://hooks.slack.com/services/***)"
    if ":" in compact and "$" in compact and len(compact) > 20:
        user = compact.split(":", 1)[0][:12]
        return f"masked({rule_id}:user={user};hash=***)"

    token = compact
    for marker in ("=", ":", "\"", "'", " "):
        if marker in token:
            token = token.split(marker)[-1]
    token = token.strip("\"'()[]{} ,;")
    if not token:
        token = compact
    if len(token) <= 8:
        masked = "*" * len(token)
    else:
        masked = f"{token[:4]}***{token[-4:]}"
    return f"masked({rule_id}:len={len(token)};sample={masked})"


def scan_text_blob(
    source_label: str,
    source_location: str,
    text: str,
    *,
    max_findings: int = 12,
) -> list[SecretMatch]:
    lowered_path = source_label.replace("\\", "/").lower()
    if is_denied_path(lowered_path):
        return []

    lowered_text = text.lower()
    findings: list[SecretMatch] = []
    for rule in SECRET_RULES:
        if len(findings) >= max_findings:
            break
        if not _path_allowed(rule, lowered_path):
            continue
        if not _keyword_match(rule, lowered_text):
            continue

        match_count = 0
        samples: list[str] = []
        seen_samples: set[str] = set()
        for match in rule.regex.finditer(text):
            match_count += 1
            if len(samples) >= MAX_SAMPLES_PER_RULE:
                continue
            masked = mask_secret_sample(rule.id, match.group(0))
            if masked in seen_samples:
                continue
            seen_samples.add(masked)
            samples.append(masked)

        if not match_count:
            continue

        findings.append(
            SecretMatch(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                category=rule.category,
                recommendation=rule.recommendation,
                consumers=rule.consumers,
                source_label=source_label,
                location=source_location,
                sample=" | ".join(samples) if samples else f"masked({rule.id})",
                match_count=match_count,
            )
        )
    return findings
