from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urljoin, urlparse

from ai_security_agent.schemas import Finding, ModuleResult

from .file_handler import cleanup_path, create_temp_workspace, extract_archive, read_text_preview, write_bytes
from .http_client import fetch_bytes, fetch_many_text, fetch_text, is_local_or_lab_target, now_iso
from .secret_scanner import scan_text_blob


TEXT_PREVIEW_LIMIT = 160
MAX_PROBE_BYTES = 4096
MAX_BINARY_PREVIEW_BYTES = 8192
MAX_DOWNLOAD_BYTES = 1_048_576
MAX_DOWNLOAD_COUNT = 4
MAX_AUDIT_FILES = 40
MAX_DYNAMIC_CANDIDATES = 12
MAX_DYNAMIC_SEEDS = 8
MAX_PROTECTED_ARCHIVE_PASSWORD_CANDIDATES = 8
MAX_STRUCTURE_HINTS = 6
MAX_STRUCTURE_FOLLOWUP_CANDIDATES = 8
MAX_STRUCTURE_FOLLOWUP_DOWNLOADS = 2
MAX_CORRELATED_DISCOVERY_SEEDS = 6
MAX_EXACT_ARTIFACT_FOLLOWUP_CANDIDATES = 3
MAX_SECRET_FINDINGS_PER_BLOB = 12
MAX_METADATA_FOLLOWUP_CANDIDATES = 24
DS_STORE_STRING_LIMIT = 20
GIT_INDEX_ENTRY_LIMIT = 80
METADATA_STRING_NOISE = ("bud1", "dsdb", "ilocblob", "bwspblob", "bplist", "showtoolbar", "showstatusbar", "showpathbar")

ARCHIVE_SUFFIXES = (".zip", ".tar.gz", ".tgz", ".tar", ".7z", ".rar")
TEXT_EXTENSIONS = (
    ".env",
    ".bak",
    ".old",
    ".sql",
    ".json",
    ".pem",
    ".key",
    ".crt",
    ".xml",
    ".cfg",
    ".conf",
    ".ini",
    ".php",
    ".txt",
    ".yml",
    ".yaml",
)
KEY_FILENAMES = {".env", ".git/config", "config.php", "config.inc.php", "settings.py", "wp-config.php"}
DOWNLOAD_PRIORITY_FILENAMES = {
    ".env",
    ".env.production",
    ".env.testing",
    ".git/config",
    ".htpasswd",
    "config.php",
    "config.inc.php",
    "settings.py",
    "wp-config.php",
    "app/etc/env.php",
    "web.config",
    "nginx.conf",
    "docker-compose.override.yml",
    "credentials.json",
    "database.json",
    "id_rsa",
    ".aws/credentials.bak",
    ".kube/config",
}
SUPPLEMENTAL_GIT_CANDIDATES = (
    ".git/HEAD",
    ".git/index",
    ".git/logs/HEAD",
    ".git/refs/heads/master",
    ".git/refs/heads/main",
)
DS_STORE_CANDIDATES = (
    ".DS_Store",
    "assets/.DS_Store",
    "public/.DS_Store",
    "static/.DS_Store",
    "uploads/.DS_Store",
)
SOURCE_METADATA_CANDIDATES = (
    "Dockerfile",
    ".gitattributes",
    "composer.json",
    "composer.lock",
    "package.json",
    "package-lock.json",
)
EDITOR_BACKUP_CANDIDATES = (
    "config.php~",
    "config.inc.php.bak",
    "config.inc.php.old",
    "inc/config.inc.php.bak",
    "include/config.inc.php.bak",
)
EMPTY_EXECUTED_CONFIG_NAMES = {
    "config.php",
    "config.inc.php",
    "inc/config.inc.php",
    "include/config.inc.php",
    "wp-config.php",
    "app/etc/env.php",
}
SENSITIVE_NAME_MARKERS = ("config", "secret", "credential", "database", "db", "key", "token")
API_PATH_RE = re.compile(r"(?i)(?:['\"])((?:/api|/v\d+/)[A-Za-z0-9_./?-]{2,120})(?:['\"])")
AUTH_PATH_RE = re.compile(r"(?i)(?:['\"])((?:/)?[A-Za-z0-9_./-]{0,80}(?:login|admin|signin|signup|auth)[A-Za-z0-9_./-]{0,80})(?:['\"])")
JS_ASSET_RE = re.compile(r"(?i)(?:['\"])([A-Za-z0-9_./-]{1,160}\.js(?:\?[A-Za-z0-9=&._-]{1,80})?)(?:['\"])")
INTERNAL_URL_RE = re.compile(
    r"(?i)\bhttps?://(?:localhost|127\.0\.0\.1|10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|[a-z0-9_-]+(?::\d{2,5})?)(?:/[^\s'\"`]{0,160})?"
)
DB_HOST_ASSIGN_RE = re.compile(r"(?im)\b(?:db_host|database_host|mysql_host|postgres_host|redis_host)\b\s*[:=]\s*['\"]?([A-Za-z0-9_.-]+)")
DATABASE_URL_HOST_RE = re.compile(r"(?i)\b(?:mysql|postgres(?:ql)?|redis)://(?:[^@\s/]+@)?([A-Za-z0-9_.-]+)")
PAGE_REFERENCE_RE = re.compile(r"(?i)(?:href|src|action)\s*=\s*['\"]([^'\"]{1,160})['\"]")
FRAMEWORK_ROUTE_RE = re.compile(
    r"(?im)(?:Route::(?:get|post|put|delete|any|match|resource)\s*\(\s*['\"]([^'\"]{1,120})['\"]|"
    r"path\s*\(\s*['\"]([^'\"]{1,120})['\"]|"
    r"app\.route\s*\(\s*['\"]([^'\"]{1,120})['\"]|"
    r"router\.(?:get|post|put|delete)\s*\(\s*['\"]([^'\"]{1,120})['\"]|"
    r"@RequestMapping\s*\(\s*['\"]([^'\"]{1,120})['\"]|"
    r"@(?:Get|Post|Put|Delete)Mapping\s*\(\s*['\"]([^'\"]{1,120})['\"])"
)
FRAMEWORK_MIDDLEWARE_RE = re.compile(
    r"(?im)\b(?:auth(?:entication)?|login_required|IsAuthenticated|permission_classes|middleware|adminMiddleware|jwt\.auth|auth:sanctum|auth:api)\b.{0,80}"
)
ROUTE_PREFIX_RE = re.compile(
    r"(?im)(?:Route::prefix\s*\(\s*['\"]([^'\"]{1,120})['\"]|"
    r"url_prefix\s*=\s*['\"]([^'\"]{1,120})['\"]|"
    r"@RequestMapping\s*\(\s*['\"]([^'\"]{1,120})['\"]|"
    r"server\.servlet\.context-path\s*[:=]\s*['\"]?([/\w.-]{1,120})|"
    r"(?:route_prefix|api_prefix|admin_path|login_path|base_path)\b\s*[:=]\s*['\"]?([/\w.-]{1,120}))"
)
CONTROLLER_HINT_RE = re.compile(r"(?i)\b([A-Z][A-Za-z0-9_]{2,}(?:Controller|Handler|ViewSet|APIView))\b")
CONFIG_ENTRYPOINT_RE = re.compile(
    r"(?im)\b(?:app_url|base_url|api_base|api_path|admin_url|admin_path|login_url|login_path|root_url|context_path|route_prefix)\b\s*[:=]\s*['\"]?([/\w.-]{2,120})"
)
DOWNLOAD_EXPORT_PATH_RE = re.compile(r"(?i)(?:['\"])((?:/)?[A-Za-z0-9_./-]{0,80}(?:download|export|backup|dump|archive)[A-Za-z0-9_./-]{0,80})(?:['\"])")
UPLOAD_IMPORT_PATH_RE = re.compile(r"(?i)(?:['\"])((?:/)?[A-Za-z0-9_./-]{0,80}(?:upload|import|avatar|attachment|file-upload)[A-Za-z0-9_./-]{0,80})(?:['\"])")
ARTIFACT_NAME_HINT_RE = re.compile(r"(?i)\b([A-Za-z0-9][A-Za-z0-9._-]{1,80}\.(?:zip|tar(?:\.gz)?|tgz|7z|rar|sql|bak))\b")

DYNAMIC_ARCHIVE_SUFFIXES = (".zip", ".tar.gz", ".7z")
DYNAMIC_TEXT_SUFFIXES = (".sql", ".bak")
GENERIC_DYNAMIC_NAMES = {"index", "home", "default", "login", "admin", "api", "app", "main"}
GENERIC_PATH_SEGMENTS = {"static", "assets", "public", "dist", "build", "js", "css", "img", "images", "downloads"}
GENERIC_STRUCTURE_SEEDS = {"routes", "route", "config", "settings", "application", "bootstrap", "artisan", "manage", "storage", "database", "admin", "api"}
GENERIC_RELATIONSHIP_COMPONENTS = {"backup", "archive", "dump", "export", "upload", "import", "file", "download"}
RELATIONSHIP_PRIORITY_COMPONENTS = {"admin", "auth", "login", "signin", "debug", "backup", "report", "reports", "export", "upload", "import"}
PROTECTED_ARCHIVE_PASSWORD_SUFFIXES = ("123", "1234", "2024", "2025", "2026", "_backup")
FRAMEWORK_PATH_SIGNATURES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("laravel", ("artisan", "routes/web.php", "routes/api.php", "app/http/controllers", "config/app.php")),
    ("django", ("manage.py", "settings.py", "urls.py", "wsgi.py", "asgi.py")),
    ("spring", ("application.properties", "application.yml", "application.yaml", "pom.xml", "src/main/resources")),
    ("wordpress", ("wp-config.php", "wp-content", "wp-includes")),
    ("thinkphp", ("thinkphp", "application/database.php", "route/route.php", "config/app.php")),
)
HIGH_VALUE_SOURCE_PATH_MARKERS = (
    "routes/",
    "controller",
    "service",
    "config/",
    "settings.py",
    "urls.py",
    "application.properties",
    "application.yml",
    "application.yaml",
    "database.php",
    "wp-config.php",
)

@dataclass(slots=True)
class BackupCandidate:
    path: str
    title: str
    severity: str
    recommendation: str
    kind: str
    inference_source: str = ""


@dataclass(slots=True)
class ProbeResult:
    candidate: BackupCandidate
    url: str
    status_code: int
    accessible: bool
    preview: str = ""
    content_type: str = ""
    error: str = ""
    metadata: dict[str, str] | None = None


@dataclass(slots=True)
class DownloadedArtifact:
    probe: ProbeResult
    saved_path: Path
    size: int
    extracted_from_archive: bool = False

    @property
    def is_archive(self) -> bool:
        name = self.saved_path.name.lower()
        return name.endswith(ARCHIVE_SUFFIXES)


@dataclass(slots=True)
class ArchiveStructureSummary:
    frameworks: list[str]
    high_value_paths: list[str]
    discovery_seeds: list[str]
    relationship_seeds: list[str]
    route_seeds: list[str]
    framework_route_seeds: list[str]
    route_prefixes: list[str]
    controller_hints: list[str]
    config_entrypoints: list[str]
    download_export_hints: list[str]
    upload_import_hints: list[str]
    artifact_name_hints: list[str]
    correlated_seeds: list[str]
    relationship_seed_items: list[dict[str, str]]


BACKUP_CANDIDATES = (
    BackupCandidate(
        path=".git/config",
        title="Exposed Git metadata",
        severity="high",
        recommendation="Remove `.git` metadata from the web root and rotate any secrets referenced by repository history.",
        kind="text",
    ),
    *(
        BackupCandidate(
            path=path,
            title="Exposed Git repository metadata",
            severity="high",
            recommendation="Remove `.git` metadata from the web root and treat repository structure as disclosed.",
            kind="binary" if path.endswith("/index") else "text",
        )
        for path in SUPPLEMENTAL_GIT_CANDIDATES
    ),
    *(
        BackupCandidate(
            path=path,
            title="Exposed macOS directory metadata",
            severity="medium",
            recommendation="Remove `.DS_Store` files from public directories and prevent development metadata from being deployed.",
            kind="binary",
        )
        for path in DS_STORE_CANDIDATES
    ),
    *(
        BackupCandidate(
            path=path,
            title="Exposed source or deployment metadata",
            severity="medium",
            recommendation="Remove source and deployment metadata from public web roots.",
            kind="text",
        )
        for path in SOURCE_METADATA_CANDIDATES
    ),
    *(
        BackupCandidate(
            path=path,
            title="Exposed editor or manual backup artifact",
            severity="medium",
            recommendation="Remove editor and manual backup files from public directories.",
            kind="text",
        )
        for path in EDITOR_BACKUP_CANDIDATES
    ),
    BackupCandidate(
        path=".env",
        title="Exposed environment configuration",
        severity="high",
        recommendation="Remove `.env` from the web root and rotate any credentials or API keys stored in it.",
        kind="text",
    ),
    BackupCandidate(
        path=".env.bak",
        title="Exposed environment backup",
        severity="high",
        recommendation="Remove environment backups from public paths and rotate any exposed credentials.",
        kind="text",
    ),
    BackupCandidate(
        path=".env.backup",
        title="Exposed environment backup",
        severity="high",
        recommendation="Remove environment backups from public paths and rotate any exposed credentials.",
        kind="text",
    ),
    BackupCandidate(
        path=".env.production",
        title="Exposed production environment configuration",
        severity="high",
        recommendation="Remove production environment files from public paths and rotate any embedded credentials or keys.",
        kind="text",
    ),
    BackupCandidate(
        path=".env.testing",
        title="Exposed testing environment configuration",
        severity="medium",
        recommendation="Remove testing environment files from public paths and audit them for reusable credentials.",
        kind="text",
    ),
    BackupCandidate(
        path="backup.zip",
        title="Exposed backup archive",
        severity="high",
        recommendation="Remove backup archives from public paths and move operational backups to non-web storage.",
        kind="archive",
    ),
    BackupCandidate(
        path="www.zip",
        title="Exposed website archive",
        severity="high",
        recommendation="Remove website archives from public paths and move operational backups to non-web storage.",
        kind="archive",
    ),
    BackupCandidate(
        path="web.zip",
        title="Exposed website archive",
        severity="high",
        recommendation="Remove website archives from public paths and move operational backups to non-web storage.",
        kind="archive",
    ),
    BackupCandidate(
        path="site.tar.gz",
        title="Exposed compressed site backup",
        severity="high",
        recommendation="Remove compressed site backups from the web root and store them outside public directories.",
        kind="archive",
    ),
    BackupCandidate(
        path="backup.tar.gz",
        title="Exposed compressed backup",
        severity="high",
        recommendation="Remove compressed site backups from public paths and store them outside public directories.",
        kind="archive",
    ),
    BackupCandidate(
        path="backup.7z",
        title="Exposed archive backup",
        severity="high",
        recommendation="Remove compressed site backups from public paths and store them outside public directories.",
        kind="archive",
    ),
    BackupCandidate(
        path="site.7z",
        title="Exposed archive backup",
        severity="high",
        recommendation="Remove compressed site backups from public paths and store them outside public directories.",
        kind="archive",
    ),
    BackupCandidate(
        path="archive.zip",
        title="Exposed archive backup",
        severity="high",
        recommendation="Remove compressed site backups from public paths and store them outside public directories.",
        kind="archive",
    ),
    BackupCandidate(
        path="dump.sql",
        title="Exposed database dump",
        severity="high",
        recommendation="Remove database dumps from public paths and rotate any exposed credentials.",
        kind="text",
    ),
    BackupCandidate(
        path="db.sql",
        title="Exposed database dump",
        severity="high",
        recommendation="Remove database dumps from public paths and rotate any exposed credentials.",
        kind="text",
    ),
    BackupCandidate(
        path="database.sql",
        title="Exposed database dump",
        severity="high",
        recommendation="Remove database dumps from public paths and rotate any exposed credentials.",
        kind="text",
    ),
    BackupCandidate(
        path="index.php.bak",
        title="Exposed PHP backup source",
        severity="medium",
        recommendation="Remove editor or manual backup files from public directories.",
        kind="text",
    ),
    BackupCandidate(
        path="config.php.bak",
        title="Exposed PHP backup source",
        severity="high",
        recommendation="Remove backup config files from public directories and rotate any credentials they contain.",
        kind="text",
    ),
    BackupCandidate(
        path="config.php.old",
        title="Exposed historical PHP config backup",
        severity="high",
        recommendation="Remove legacy config backups from public directories and rotate any credentials they contain.",
        kind="text",
    ),
    BackupCandidate(
        path="database.json",
        title="Exposed database configuration export",
        severity="high",
        recommendation="Remove configuration exports from public paths and rotate any embedded credentials.",
        kind="text",
    ),
    BackupCandidate(
        path="config.inc.php",
        title="Exposed PHP include configuration",
        severity="high",
        recommendation="Remove PHP include configuration files from public paths and rotate any embedded credentials.",
        kind="text",
    ),
    BackupCandidate(
        path="wp-config.php",
        title="Exposed WordPress configuration",
        severity="high",
        recommendation="Remove WordPress configuration files from public paths and rotate all embedded secrets.",
        kind="text",
    ),
    BackupCandidate(
        path="app/etc/env.php",
        title="Exposed framework environment configuration",
        severity="high",
        recommendation="Remove framework environment configuration files from public paths and rotate embedded credentials or keys.",
        kind="text",
    ),
    BackupCandidate(
        path="credentials.json",
        title="Exposed credential export",
        severity="high",
        recommendation="Remove credential exports from public paths and rotate any embedded keys or credentials.",
        kind="text",
    ),
    BackupCandidate(
        path=".htpasswd",
        title="Exposed htpasswd credential file",
        severity="high",
        recommendation="Remove htpasswd files from public paths and rotate the protected accounts.",
        kind="text",
    ),
    BackupCandidate(
        path=".htaccess",
        title="Exposed htaccess configuration marker",
        severity="medium",
        recommendation="Do not expose Apache access-control configuration files from public paths.",
        kind="text",
    ),
    BackupCandidate(
        path="id_rsa",
        title="Exposed private key material",
        severity="critical",
        recommendation="Remove private keys from public paths immediately and rotate any systems that trust them.",
        kind="text",
    ),
    BackupCandidate(
        path="docker-compose.override.yml",
        title="Exposed Docker override configuration",
        severity="medium",
        recommendation="Remove deployment override files from public paths and audit them for embedded secrets.",
        kind="text",
    ),
    BackupCandidate(
        path="nginx.conf",
        title="Exposed web server configuration",
        severity="medium",
        recommendation="Remove server configuration files from public paths and review them for internal paths or secrets.",
        kind="text",
    ),
    BackupCandidate(
        path="web.config",
        title="Exposed web server configuration",
        severity="medium",
        recommendation="Remove server configuration files from public paths and review them for internal paths or secrets.",
        kind="text",
    ),
    BackupCandidate(
        path=".aws/credentials.bak",
        title="Exposed AWS credential backup",
        severity="high",
        recommendation="Remove cloud credential backups from public paths and rotate any affected access keys immediately.",
        kind="text",
    ),
    BackupCandidate(
        path=".kube/config",
        title="Exposed Kubernetes client configuration",
        severity="high",
        recommendation="Remove Kubernetes client configuration from public paths and rotate any embedded cluster credentials or tokens.",
        kind="text",
    ),
    BackupCandidate(
        path="index.php~",
        title="Exposed editor backup source",
        severity="medium",
        recommendation="Remove editor backup artifacts from public directories.",
        kind="text",
    ),
)


def _infer_dynamic_candidates(target_url: str) -> list[BackupCandidate]:
    seeds = _collect_dynamic_name_seeds(target_url)
    candidates: list[BackupCandidate] = []
    seen_paths = {candidate.path for candidate in BACKUP_CANDIDATES}

    for name in seeds:
        for path in _build_dynamic_candidate_paths(name):
            if path in seen_paths:
                continue
            seen_paths.add(path)
            candidates.append(_make_dynamic_candidate(path))
            if len(candidates) >= MAX_DYNAMIC_CANDIDATES:
                return candidates
    return candidates


def _collect_dynamic_name_seeds(target_url: str) -> list[str]:
    parsed = urlparse(target_url)
    path_seeds: list[str] = []
    for segment in parsed.path.split("/"):
        cleaned = _normalize_dynamic_seed(segment)
        if cleaned:
            path_seeds.append(cleaned)

    response = fetch_text(target_url, timeout=1.5, max_bytes=8192)
    page_seeds: list[str] = []
    if response.ok and response.text:
        for match in PAGE_REFERENCE_RE.finditer(response.text):
            reference = match.group(1)
            cleaned_parts = _extract_reference_seed_parts(reference)
            page_seeds.extend(cleaned_parts)

    ordered = _unique_preserve_order(path_seeds + page_seeds)
    return ordered[:MAX_DYNAMIC_SEEDS]


def _normalize_dynamic_seed(value: str) -> str:
    lowered = value.strip().lower()
    if not lowered:
        return ""
    if "." in lowered:
        lowered = lowered.split(".", 1)[0]
    lowered = re.sub(r"[^a-z0-9_-]+", "", lowered)
    if len(lowered) < 3:
        return ""
    return lowered


def _extract_reference_seed_parts(reference: str) -> list[str]:
    reference_path = reference.split("?", 1)[0].split("#", 1)[0].strip()
    if not reference_path:
        return []
    raw_parts = [part for part in reference_path.rstrip("/").split("/") if part]
    seeds: list[str] = []
    for part in raw_parts[-2:]:
        cleaned = _normalize_dynamic_seed(part)
        if not cleaned or cleaned in GENERIC_DYNAMIC_NAMES or cleaned in GENERIC_PATH_SEGMENTS:
            continue
        seeds.append(cleaned)
    return seeds


def _build_dynamic_candidate_paths(seed: str) -> list[str]:
    related_names = _expand_dynamic_seed_names(seed)
    paths: list[str] = []
    for name in related_names:
        for suffix in DYNAMIC_ARCHIVE_SUFFIXES + DYNAMIC_TEXT_SUFFIXES:
            paths.append(f"{name}{suffix}")
        for archive_suffix in DYNAMIC_ARCHIVE_SUFFIXES:
            paths.append(f"{name}_backup{archive_suffix}")
            paths.append(f"{name}-backup{archive_suffix}")
    return _unique_preserve_order(paths)


def _build_structure_followup_candidate_paths(seed: str) -> list[str]:
    related_names = _expand_dynamic_seed_names(seed)
    paths: list[str] = []
    for name in related_names:
        for archive_suffix in DYNAMIC_ARCHIVE_SUFFIXES:
            paths.append(f"{name}{archive_suffix}")
            paths.append(f"{name}_backup{archive_suffix}")
            paths.append(f"{name}-backup{archive_suffix}")
            paths.append(f"{name}.src{archive_suffix}")
        for text_suffix in (".bak", ".old", ".sql", ".zip"):
            paths.append(f"{name}{text_suffix}")
    return _unique_preserve_order(paths)


def _build_metadata_followup_candidates(results: list[ProbeResult], existing_paths: set[str]) -> list[BackupCandidate]:
    candidates: list[BackupCandidate] = []
    seen = set(existing_paths)
    for result in results:
        metadata = result.metadata or {}
        evidence_kind = metadata.get("evidence_kind", "")
        if evidence_kind not in {"ds_store", "git_index"}:
            continue
        entries = [
            item.strip().lstrip("/")
            for item in str(metadata.get("entries", "")).split(",")
            if item.strip()
        ]
        for entry in entries:
            for path in _metadata_entry_followup_paths(entry):
                if path in seen:
                    continue
                seen.add(path)
                candidates.append(_make_metadata_followup_candidate(path, evidence_kind))
                if len(candidates) >= MAX_METADATA_FOLLOWUP_CANDIDATES:
                    return candidates
    return candidates


def _metadata_entry_followup_paths(entry: str) -> list[str]:
    cleaned = entry.strip().replace("\\", "/").lstrip("/")
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    if not cleaned or ".." in cleaned or cleaned.startswith(".git/"):
        return []
    lowered = cleaned.lower()
    basename = PurePosixPath(cleaned).name
    paths: list[str] = []
    if basename == ".DS_Store":
        return []
    if cleaned.startswith(".") and basename not in SOURCE_METADATA_CANDIDATES and not lowered.startswith(".env"):
        return []
    if "/" not in cleaned and "." not in cleaned and not basename.isupper() and basename not in SOURCE_METADATA_CANDIDATES and len(cleaned) >= 2:
        paths.append(f"{cleaned}/.DS_Store")
    if lowered.endswith((".bak", ".old", "~", ".env", ".sql", ".json", ".yml", ".yaml")):
        paths.append(cleaned)
    if basename in SOURCE_METADATA_CANDIDATES:
        paths.append(cleaned)
    return _unique_preserve_order(paths)


def _make_metadata_followup_candidate(path: str, source: str) -> BackupCandidate:
    lowered = path.lower()
    if lowered.endswith(".ds_store"):
        return BackupCandidate(
            path=path,
            title="Metadata-inferred macOS directory metadata",
            severity="medium",
            recommendation="Remove `.DS_Store` files from public directories and prevent development metadata from being deployed.",
            kind="binary",
            inference_source=source,
        )
    return BackupCandidate(
        path=path,
        title="Metadata-inferred backup or source artifact",
        severity="medium",
        recommendation="Remove metadata-discovered backup or source artifacts from public web roots.",
        kind="text",
        inference_source=source,
    )


def _build_exact_artifact_followup_paths(artifact_name_hints: list[str]) -> list[str]:
    paths: list[str] = []
    for name in artifact_name_hints[:MAX_STRUCTURE_HINTS]:
        cleaned = name.strip().lstrip("/")
        if not cleaned or "/" in cleaned or "\\" in cleaned:
            continue
        lowered = cleaned.lower()
        if not (lowered.endswith(ARCHIVE_SUFFIXES) or lowered.endswith(DYNAMIC_TEXT_SUFFIXES)):
            continue
        paths.append(cleaned)
    return _unique_preserve_order(paths)[:MAX_EXACT_ARTIFACT_FOLLOWUP_CANDIDATES]


def _expand_dynamic_seed_names(seed: str) -> list[str]:
    names = [seed]
    compact = seed.replace("-", "").replace("_", "")
    if compact and compact != seed and len(compact) >= 3:
        names.append(compact)
    if "-" in seed:
        names.extend(part for part in seed.split("-") if len(part) >= 3 and part not in GENERIC_DYNAMIC_NAMES)
    if "_" in seed:
        names.extend(part for part in seed.split("_") if len(part) >= 3 and part not in GENERIC_DYNAMIC_NAMES)
    return _unique_preserve_order(names)


def _make_dynamic_candidate(path: str) -> BackupCandidate:
    lowered = path.lower()
    if lowered.endswith(ARCHIVE_SUFFIXES):
        return BackupCandidate(
            path=path,
            title="Dynamically inferred archive backup",
            severity="high",
            recommendation="Remove dynamically discoverable backup archives from public paths and store them outside web roots.",
            kind="archive",
            inference_source="dynamic_seed",
        )
    return BackupCandidate(
        path=path,
        title="Dynamically inferred backup or source artifact",
        severity="medium",
        recommendation="Remove dynamically discoverable backup, dump, or source artifacts from public paths.",
        kind="text",
        inference_source="dynamic_seed",
    )


def _sanitize_preview(text: str) -> str:
    compact = " ".join(text.split())
    return compact[:TEXT_PREVIEW_LIMIT]


def _probe_path(target_url: str, candidate: BackupCandidate) -> ProbeResult:
    candidate_url = urljoin(target_url.rstrip("/") + "/", candidate.path)
    response = fetch_text(candidate_url, timeout=1.0, max_bytes=MAX_PROBE_BYTES)
    headers = response.headers or {}
    content_type = headers.get("Content-Type", headers.get("content-type", "")) if headers else ""

    if response.status_code in {200, 206, 301, 302, 403}:
        preview = ""
        if candidate.kind == "text" and response.text:
            preview = _sanitize_preview(response.text)
        metadata: dict[str, str] = {}
        if response.status_code in {200, 206}:
            metadata.update(_probe_content_metadata(candidate, response.text))
        return ProbeResult(
            candidate=candidate,
            url=candidate_url,
            status_code=response.status_code,
            accessible=True,
            preview=preview,
            content_type=content_type,
            metadata=metadata,
        )

    return ProbeResult(
        candidate=candidate,
        url=candidate_url,
        status_code=response.status_code,
        accessible=False,
        content_type=content_type,
        error=response.error,
    )


def _probe_paths_batch(target_url: str, candidates: list[BackupCandidate]) -> list[ProbeResult]:
    results = [_probe_path(target_url, candidate) for candidate in candidates]
    return _enrich_binary_probe_results(results)


def _probe_content_metadata(candidate: BackupCandidate, text: str) -> dict[str, str]:
    lowered_path = candidate.path.lower()
    metadata: dict[str, str] = {}
    if lowered_path.endswith(".git/config") and "[core]" in text and "repositoryformatversion" in text.lower():
        metadata["evidence_kind"] = "git_config"
    elif lowered_path.endswith(".git/head") and text.strip().startswith("ref:"):
        metadata["evidence_kind"] = "git_head"
    elif "/.git/logs/" in lowered_path and text.strip():
        metadata["evidence_kind"] = "git_log"
    elif "/.git/refs/" in lowered_path and re.search(r"\b[0-9a-f]{40}\b", text.strip(), flags=re.I):
        metadata["evidence_kind"] = "git_ref"
    elif lowered_path.endswith(".php") and not text.strip():
        metadata["evidence_kind"] = "executed_empty_php"
    elif lowered_path.endswith("dockerfile") and text.lower().lstrip().startswith("from "):
        metadata["evidence_kind"] = "deployment_metadata"
    elif PurePosixPath(candidate.path).name in SOURCE_METADATA_CANDIDATES and text.strip():
        metadata["evidence_kind"] = "source_metadata"
    elif lowered_path.endswith((".bak", ".old", "~")) and text.strip():
        metadata["evidence_kind"] = "editor_backup"
    elif lowered_path.endswith((".json", ".lock")) and text.strip():
        metadata["evidence_kind"] = "source_metadata"
    return metadata


def _enrich_binary_probe_results(results: list[ProbeResult]) -> list[ProbeResult]:
    for result in results:
        if not result.accessible or result.status_code not in {200, 206}:
            continue
        lowered = result.candidate.path.lower()
        if result.candidate.kind != "binary" and not lowered.endswith(".ds_store"):
            continue
        response = fetch_bytes(result.url, timeout=1.0, max_bytes=MAX_BINARY_PREVIEW_BYTES)
        if not response.ok:
            continue
        content = response.content
        metadata = dict(result.metadata or {})
        if lowered.endswith(".git/index") and content.startswith(b"DIRC"):
            metadata["evidence_kind"] = "git_index"
            entries = _extract_git_index_paths(content, limit=GIT_INDEX_ENTRY_LIMIT)
            if not entries:
                entries = _extract_ascii_strings(content, limit=GIT_INDEX_ENTRY_LIMIT)
            metadata["entries"] = ", ".join(entries)
        elif lowered.endswith(".ds_store") and content.startswith(b"\x00\x00\x00\x01Bud1"):
            metadata["evidence_kind"] = "ds_store"
            metadata["entries"] = ", ".join(_extract_ascii_strings(content, limit=DS_STORE_STRING_LIMIT))
        result.metadata = metadata
        if not result.preview and metadata.get("entries"):
            result.preview = f"entries={metadata['entries']}"[:TEXT_PREVIEW_LIMIT]
    return results


def _extract_ascii_strings(content: bytes, *, limit: int) -> list[str]:
    strings: list[str] = []
    for encoding in ("utf-16-be", "utf-16-le"):
        decoded = content.decode(encoding, errors="ignore")
        for match in re.finditer(r"[A-Za-z0-9_.\-/]{3,}", decoded):
            _append_metadata_string(strings, match.group(0), limit=limit)
            if len(strings) >= limit:
                return strings
    for match in re.finditer(rb"[A-Za-z0-9_.\-/]{3,}", content):
        _append_metadata_string(strings, match.group(0).decode("ascii", errors="ignore"), limit=limit)
        if len(strings) >= limit:
            return strings
    return strings


def _extract_git_index_paths(content: bytes, *, limit: int) -> list[str]:
    if len(content) < 12 or not content.startswith(b"DIRC"):
        return []
    try:
        entry_count = int.from_bytes(content[8:12], "big")
    except Exception:
        return []
    if entry_count <= 0 or entry_count > 100_000:
        return []
    paths: list[str] = []
    offset = 12
    for _ in range(entry_count):
        if offset + 62 > len(content):
            break
        flags = int.from_bytes(content[offset + 60 : offset + 62], "big")
        name_len = flags & 0x0FFF
        path_start = offset + 62
        if name_len < 0x0FFF and path_start + name_len <= len(content):
            raw_path = content[path_start : path_start + name_len]
            path_end = path_start + name_len
        else:
            path_end = content.find(b"\x00", path_start)
            if path_end < 0:
                break
            raw_path = content[path_start:path_end]
        path = raw_path.decode("utf-8", errors="ignore").strip()
        if path and path not in paths:
            paths.append(path)
            if len(paths) >= limit:
                break
        entry_size = 62 + len(raw_path) + 1
        offset += (entry_size + 7) & ~7
    return paths


def _append_metadata_string(strings: list[str], value: str, *, limit: int) -> None:
    item = value.strip()
    lowered = item.lower()
    if not item or item in strings:
        return
    if any(marker in lowered for marker in METADATA_STRING_NOISE):
        return
    if len(item) > 120:
        return
    strings.append(item)


def _is_confirmed_exposure(result: ProbeResult) -> bool:
    if result.status_code not in {200, 206}:
        return False
    metadata = result.metadata or {}
    if metadata.get("evidence_kind") == "executed_empty_php":
        return False
    lowered = result.candidate.path.lower()
    if any(lowered == item or lowered.endswith("/" + item) for item in EMPTY_EXECUTED_CONFIG_NAMES) and not result.preview:
        return False
    return True


def _backup_context_for_result(result: ProbeResult, *, group_key: str = "") -> dict[str, str | int]:
    metadata = dict(result.metadata or {})
    evidence_kind = str(metadata.get("evidence_kind", "")).strip()
    if not evidence_kind:
        lowered = result.candidate.path.lower()
        if lowered.endswith(ARCHIVE_SUFFIXES):
            evidence_kind = "archive"
        elif lowered.endswith(TEXT_EXTENSIONS):
            evidence_kind = "text_artifact"
        else:
            evidence_kind = "artifact"
    return {
        "path": result.candidate.path,
        "status_code": result.status_code,
        "artifact_type": result.candidate.kind,
        "evidence_kind": evidence_kind,
        "group_key": group_key or result.candidate.path,
    }


def _build_exposure_finding(result: ProbeResult) -> Finding:
    evidence = f"{result.candidate.path} -> HTTP {result.status_code}"
    if result.content_type:
        evidence = f"{evidence}; content_type={result.content_type}"
    if result.metadata and result.metadata.get("evidence_kind"):
        evidence = f"{evidence}; evidence_kind={result.metadata['evidence_kind']}"
    if result.metadata and result.metadata.get("entries"):
        evidence = f"{evidence}; entries={result.metadata['entries']}"
    if result.preview:
        evidence = f"{evidence}; preview={result.preview}"

    return _annotate_finding(
        Finding(
        title=result.candidate.title,
        severity=result.candidate.severity,  # type: ignore[arg-type]
        location=result.url,
        evidence=evidence,
        verified=True,
        recommendation=result.candidate.recommendation,
        metadata={"backup_context": _backup_context_for_result(result)},
        ),
        category="exposure",
        consumers=("orchestrator", "sql", "js", "poc"),
    )


def _build_git_metadata_group_finding(results: list[ProbeResult]) -> Finding | None:
    confirmed = [
        item
        for item in results
        if item.candidate.path.lower().startswith(".git/")
        and _is_confirmed_exposure(item)
        and (item.metadata or {}).get("evidence_kind") in {"git_config", "git_head", "git_index", "git_log", "git_ref"}
    ]
    if not confirmed:
        return None
    paths = [item.candidate.path for item in confirmed]
    evidence_parts = []
    for item in confirmed:
        detail = f"{item.candidate.path}:HTTP {item.status_code}"
        kind = (item.metadata or {}).get("evidence_kind")
        if kind:
            detail = f"{detail}:{kind}"
        entries = (item.metadata or {}).get("entries")
        if entries:
            detail = f"{detail}:entries={entries}"
        elif item.preview:
            detail = f"{detail}:preview={item.preview}"
        evidence_parts.append(detail)
    context = {
        "path": ".git/",
        "status_code": 200,
        "artifact_type": "git_metadata",
        "evidence_kind": "git_repository_metadata",
        "group_key": "git_metadata",
        "members": paths,
    }
    return _annotate_finding(
        Finding(
            title="Exposed Git repository metadata/source inventory",
            severity="high",
            location=confirmed[0].url.rsplit("/", 2)[0] + "/.git/",
            evidence="evidence_kind=git_repository_metadata; Accessible Git metadata members: " + " | ".join(evidence_parts),
            verified=True,
            recommendation="Remove `.git` metadata from the web root and treat repository structure, commit refs, and source inventory as disclosed.",
            metadata={"backup_context": context},
        ),
        category="exposure",
        consumers=("orchestrator", "sql", "js", "poc"),
    )


def _exposure_findings_from_results(results: list[ProbeResult]) -> list[Finding]:
    findings: list[Finding] = []
    git_group = _build_git_metadata_group_finding(results)
    if git_group is not None:
        findings.append(git_group)
    for item in results:
        if not _is_confirmed_exposure(item):
            if item.status_code == 403:
                findings.append(_build_exposure_finding(item))
            elif (item.metadata or {}).get("evidence_kind") == "executed_empty_php":
                findings.append(_build_executed_config_auxiliary_finding(item))
            continue
        if item.candidate.path.lower().startswith(".git/"):
            continue
        findings.append(_build_exposure_finding(item))
    return findings


def _should_download(result: ProbeResult) -> bool:
    if result.status_code not in {200, 206}:
        return False
    if result.candidate.kind == "archive":
        return True
    lowered = result.candidate.path.lower()
    return lowered in DOWNLOAD_PRIORITY_FILENAMES or lowered.endswith(TEXT_EXTENSIONS)


def _download_candidate(result: ProbeResult, workspace: Path) -> tuple[DownloadedArtifact | None, str]:
    response = fetch_bytes(result.url, timeout=2.0, max_bytes=MAX_DOWNLOAD_BYTES)
    if not response.ok:
        return None, response.error or f"download failed: HTTP {response.status_code}"

    filename = Path(result.candidate.path).name or "downloaded.bin"
    saved_path = write_bytes(workspace / filename, response.content)
    return DownloadedArtifact(probe=result, saved_path=saved_path, size=len(response.content)), ""


def _build_controlled_password_candidates(artifact: DownloadedArtifact, target_url: str) -> list[str]:
    parsed = urlparse(target_url)
    seeds = _collect_dynamic_name_seeds(target_url)
    host_seed = _normalize_dynamic_seed(parsed.hostname or "")
    artifact_seed = _normalize_dynamic_seed(artifact.saved_path.stem)
    base_names = _unique_preserve_order([artifact_seed, host_seed, *seeds])

    candidates: list[str] = []
    for name in base_names:
        if not name:
            continue
        candidates.append(name)
        for suffix in PROTECTED_ARCHIVE_PASSWORD_SUFFIXES:
            candidates.append(f"{name}{suffix}")
    return _unique_preserve_order(candidates)[:MAX_PROTECTED_ARCHIVE_PASSWORD_CANDIDATES]


def _build_structure_followup_candidates(extracted_files: list[Path], existing_paths: set[str]) -> list[BackupCandidate]:
    structure = _summarize_archive_structure(extracted_files)
    candidates: list[BackupCandidate] = []
    seen_paths = set(existing_paths)
    for path in _build_exact_artifact_followup_paths(structure.artifact_name_hints):
        if path in seen_paths:
            continue
        seen_paths.add(path)
        candidate = _make_structure_followup_candidate(path)
        candidate.inference_source = "exact_artifact_name"
        candidates.append(candidate)
        if len(candidates) >= MAX_STRUCTURE_FOLLOWUP_CANDIDATES:
            return candidates

    prioritized_seeds = _prioritize_structure_followup_seeds(structure)
    candidate_paths_by_seed = {
        seed: _build_structure_followup_candidate_paths(seed) for seed in prioritized_seeds
    }
    max_paths_per_seed = max((len(paths) for paths in candidate_paths_by_seed.values()), default=0)
    for index in range(max_paths_per_seed):
        for seed in prioritized_seeds:
            paths = candidate_paths_by_seed.get(seed, [])
            if index >= len(paths):
                continue
            path = paths[index]
            if path in seen_paths:
                continue
            seen_paths.add(path)
            candidate = _make_structure_followup_candidate(path)
            candidate.inference_source = _structure_seed_inference_source(seed, structure)
            candidates.append(candidate)
            if len(candidates) >= MAX_STRUCTURE_FOLLOWUP_CANDIDATES:
                return candidates
    return candidates


def _build_download_finding(artifact: DownloadedArtifact) -> Finding:
    return _annotate_finding(
        Finding(
        title=f"Downloaded exposed backup artifact: {artifact.saved_path.name}",
        severity="medium",
        location=artifact.probe.url,
        evidence=f"downloaded_size={artifact.size} bytes; source={artifact.probe.candidate.path}",
        verified=True,
        recommendation="Keep backups, dumps, and source snapshots outside public web roots.",
        ),
        category="artifact_download",
        consumers=("orchestrator",),
    )


def _build_structure_followup_exposure_finding(result: ProbeResult) -> Finding:
    evidence = f"{result.candidate.path} -> HTTP {result.status_code}; inference=structure_followup"
    if result.candidate.inference_source:
        evidence = f"{evidence}; inference_source={result.candidate.inference_source}"
    return _annotate_finding(
        Finding(
        title="Structure-inferred backup follow-up artifact",
        severity="medium",
        location=result.url,
        evidence=evidence,
        verified=True,
        recommendation="Treat this as a second-pass bounded discovery result derived from recovered source structure and remove the exposed artifact from public access.",
        ),
        category="exposure",
        consumers=("orchestrator", "sql", "js", "poc"),
    )


def _build_executed_config_auxiliary_finding(result: ProbeResult) -> Finding:
    return _annotate_finding(
        Finding(
            title="Configuration path executed without source disclosure",
            severity="info",
            location=result.url,
            evidence=f"{result.candidate.path} -> HTTP {result.status_code}; evidence_kind=executed_empty_php; not counted as confirmed source exposure",
            verified=False,
            recommendation="Keep this as inventory only unless the raw source or sensitive configuration content becomes readable.",
            metadata={"backup_context": _backup_context_for_result(result)},
        ),
        category="followup_hint",
        consumers=("orchestrator",),
    )


def _build_password_protected_archive_finding(
    artifact: DownloadedArtifact,
    error: str,
    *,
    password_attempt_count: int,
) -> Finding:
    retry_profile = _archive_retry_profile_for_outcome("password_required")
    return _annotate_finding(
        Finding(
        title="Password-protected archive exposure requires follow-up review",
        severity="medium",
        location=artifact.probe.url,
        evidence=(
            f"archive={artifact.saved_path.name}; archive_type=zip; outcome=password_required; "
            f"password_strategy=controlled_weak_password_candidates; strategy_supported=true; "
            f"weak_password_support=zip_only; password_attempt_count={password_attempt_count}; "
            f"{_archive_retry_evidence_fields(retry_profile)}; "
            f"extraction_error={error}"
        ),
        verified=True,
        recommendation="Review this exposed archive manually, validate whether it is encrypted on purpose, and remove it from public access.",
        ),
        category="archive_followup",
        consumers=("orchestrator", "poc"),
    )


def _build_non_zip_password_protected_archive_finding(
    artifact: DownloadedArtifact,
    error: str,
    *,
    outcome: str,
    archive_type: str,
    password_attempt_count: int,
    strategy_supported: bool,
) -> Finding:
    return _annotate_finding(
        Finding(
        title="Protected non-zip archive requires manual follow-up review",
        severity="medium",
        location=artifact.probe.url,
        evidence=(
            f"archive={artifact.saved_path.name}; archive_type={archive_type}; outcome={outcome}; extraction_error={error}; "
            f"password_strategy=controlled_non_zip_password_candidates; password_attempt_count={password_attempt_count}; "
            f"strategy_supported={'true' if strategy_supported else 'false'}; "
            f"{_archive_retry_evidence_fields(_archive_retry_profile_for_outcome(outcome))}"
        ),
        verified=True,
        recommendation="Review this protected non-zip archive manually. The current automation only uses a tiny controlled password set and does not perform heavy cracking.",
        ),
        category="archive_followup",
        consumers=("orchestrator", "poc"),
    )


def _build_non_zip_password_strategy_finding(artifact: DownloadedArtifact, archive_type: str, attempted_passwords: list[str]) -> Finding:
    attempted = ",".join(password or "<empty>" for password in attempted_passwords[:MAX_PROTECTED_ARCHIVE_PASSWORD_CANDIDATES])
    return _annotate_finding(
        Finding(
        title="Protected non-zip archive received controlled password handling",
        severity="info",
        location=artifact.probe.url,
        evidence=(
            f"archive={artifact.saved_path.name}; archive_type={archive_type}; outcome=controlled_password_handling_attempted; "
            f"password_strategy=controlled_non_zip_password_candidates; attempted_passwords={attempted}"
        ),
        verified=True,
        recommendation="Use this as a bounded handling record only. If the archive still matters, continue with authorized manual review rather than brute force.",
        ),
        category="archive_followup",
        consumers=("orchestrator",),
    )


def _build_non_zip_unpacker_gap_finding(artifact: DownloadedArtifact, archive_type: str) -> Finding:
    return _annotate_finding(
        Finding(
        title="Non-zip archive handling is limited by missing optional unpacker",
        severity="medium",
        location=artifact.probe.url,
        evidence=(
            f"archive={artifact.saved_path.name}; archive_type={archive_type}; outcome=missing_optional_unpacker; "
            f"{_archive_retry_evidence_fields(_archive_retry_profile_for_outcome('missing_optional_unpacker'))}"
        ),
        verified=True,
        recommendation="Install and validate the optional unpacker only where this D-side environment is meant to support additional archive formats, then re-run bounded handling.",
        ),
        category="archive_followup",
        consumers=("orchestrator",),
    )


def _build_non_zip_password_exhausted_finding(artifact: DownloadedArtifact, archive_type: str, attempt_count: int) -> Finding:
    return _annotate_finding(
        Finding(
        title="Protected non-zip archive resisted controlled password candidates",
        severity="medium",
        location=artifact.probe.url,
        evidence=(
            f"archive={artifact.saved_path.name}; archive_type={archive_type}; outcome=password_attempts_exhausted; "
            f"password_attempt_count={attempt_count}; password_strategy=controlled_non_zip_password_candidates; "
            f"{_archive_retry_evidence_fields(_archive_retry_profile_for_outcome('password_attempts_exhausted'))}"
        ),
        verified=True,
        recommendation="Keep this as a bounded handling result only and escalate to authorized manual review if the archive remains important.",
        ),
        category="archive_followup",
        consumers=("orchestrator", "poc"),
    )


def _build_non_zip_password_strategy_unsupported_finding(artifact: DownloadedArtifact, archive_type: str) -> Finding:
    return _annotate_finding(
        Finding(
        title="Protected non-zip archive format is outside the controlled password strategy",
        severity="medium",
        location=artifact.probe.url,
        evidence=(
            f"archive={artifact.saved_path.name}; archive_type={archive_type}; outcome=password_strategy_unsupported; "
            f"password_strategy=controlled_non_zip_password_candidates; strategy_supported=false; "
            f"{_archive_retry_evidence_fields(_archive_retry_profile_for_outcome('password_strategy_unsupported'))}"
        ),
        verified=True,
        recommendation="Keep this explicit boundary visible and only extend format coverage after validating safe bounded handling for that archive type.",
        ),
        category="archive_followup",
        consumers=("orchestrator", "poc"),
    )


def _build_archive_extraction_failure_finding(artifact: DownloadedArtifact, error: str) -> Finding:
    return _annotate_finding(
        Finding(
        title="Exposed archive could not be automatically extracted",
        severity="medium",
        location=artifact.probe.url,
        evidence=f"archive={artifact.saved_path.name}; extraction_error={error}",
        verified=True,
        recommendation="Review this exposed archive manually and confirm whether unsupported format, corruption, or tooling gaps are blocking static audit.",
        ),
        category="archive_followup",
        consumers=("orchestrator",),
    )


def _make_structure_followup_candidate(path: str) -> BackupCandidate:
    return BackupCandidate(
        path=path,
        title="Structure-inferred backup follow-up artifact",
        severity="medium",
        recommendation="Remove structure-inferred backup artifacts from public paths and review why recovered source layout made them guessable.",
        kind="archive" if path.lower().endswith(ARCHIVE_SUFFIXES) else "text",
        inference_source="generic_structure_seed",
    )


def _build_weak_password_archive_finding(artifact: DownloadedArtifact, password: str) -> Finding:
    masked = password if password else "<empty-password>"
    return _annotate_finding(
        Finding(
        title="Exposed archive was extractable with a weak password",
        severity="high",
        location=artifact.probe.url,
        evidence=f"archive={artifact.saved_path.name}; weak_password={masked}",
        verified=True,
        recommendation="Treat the archive as disclosed content, rotate any embedded secrets, and remove weak or empty archive passwords from operational practice.",
        ),
        category="weak_archive_password",
        consumers=("orchestrator", "poc"),
    )


def _audit_artifact(artifact: DownloadedArtifact) -> list[Finding]:
    text = read_text_preview(artifact.saved_path)
    return _audit_text_blob(
        source_label=str(artifact.saved_path.name),
        source_location=artifact.probe.url,
        text=text,
    )


def _audit_extracted_files(archive_probe: ProbeResult, extracted_files: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for file_path in extracted_files[:MAX_AUDIT_FILES]:
        lowered = file_path.name.lower()
        if not _looks_textual(file_path):
            continue
        text = read_text_preview(file_path)
        location = f"{archive_probe.url}::{file_path.name}"
        findings.extend(_audit_text_blob(source_label=file_path.name, source_location=location, text=text))
        if lowered in KEY_FILENAMES or any(marker in lowered for marker in SENSITIVE_NAME_MARKERS):
            findings.append(
                _annotate_finding(
                Finding(
                    title="High-value configuration or secret-bearing file recovered from archive",
                    severity="medium",
                    location=location,
                    evidence=f"Recovered file name `{file_path.name}` suggests configuration, credentials, or application secrets.",
                    verified=True,
                    recommendation="Review whether this file should ever be present in deployable or downloadable backups.",
                ),
                category="followup_hint",
                consumers=("orchestrator", "sql", "js", "poc"),
                )
            )
    findings.extend(_extract_archive_structure_findings(archive_probe, extracted_files))
    return _deduplicate_findings(findings)


def _summarize_archive_structure(extracted_files: list[Path]) -> ArchiveStructureSummary:
    relative_paths = _unique_preserve_order(path.as_posix() for path in extracted_files[:MAX_AUDIT_FILES])
    frameworks = _detect_framework_fingerprints(relative_paths)
    high_value_paths = _extract_high_value_source_paths(relative_paths)
    route_seeds = _derive_route_like_seeds_from_paths(relative_paths)
    framework_route_seeds = _derive_route_like_seeds_from_text(extracted_files)
    (
        route_prefixes,
        controller_hints,
        config_entrypoints,
        download_export_hints,
        upload_import_hints,
        artifact_name_hints,
    ) = _collect_structure_relationship_hints(extracted_files)
    correlated_seeds = _derive_correlated_discovery_seeds(
        framework_route_seeds,
        route_prefixes,
        controller_hints,
        config_entrypoints,
        download_export_hints,
        artifact_name_hints,
        _derive_relationship_followup_seeds(
            route_prefixes=route_prefixes,
            controller_hints=controller_hints,
            config_entrypoints=config_entrypoints,
            download_export_hints=download_export_hints,
            upload_import_hints=upload_import_hints,
            artifact_name_hints=artifact_name_hints,
        ),
    )
    relationship_seeds = _derive_relationship_followup_seeds(
        route_prefixes=route_prefixes,
        controller_hints=controller_hints,
        config_entrypoints=config_entrypoints,
        download_export_hints=download_export_hints,
        upload_import_hints=upload_import_hints,
        artifact_name_hints=artifact_name_hints,
    )
    discovery_seeds = _derive_structure_followup_seeds(
        relative_paths,
        frameworks,
        route_seeds,
        framework_route_seeds,
        correlated_seeds,
        relationship_seeds,
        controller_hints,
        artifact_name_hints,
    )
    return ArchiveStructureSummary(
        frameworks=frameworks,
        high_value_paths=high_value_paths,
        discovery_seeds=discovery_seeds,
        relationship_seeds=relationship_seeds,
        route_seeds=route_seeds,
        framework_route_seeds=framework_route_seeds,
        route_prefixes=route_prefixes,
        controller_hints=controller_hints,
        config_entrypoints=config_entrypoints,
        download_export_hints=download_export_hints,
        upload_import_hints=upload_import_hints,
        artifact_name_hints=artifact_name_hints,
        correlated_seeds=correlated_seeds,
        relationship_seed_items=_build_relationship_followup_items(relationship_seeds),
    )


def _audit_text_blob(source_label: str, source_location: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    secret_matches = scan_text_blob(
        source_label=source_label,
        source_location=source_location,
        text=text,
        max_findings=MAX_SECRET_FINDINGS_PER_BLOB,
    )
    for match in secret_matches:
        findings.append(
            _annotate_finding(
                Finding(
                    title=match.title,
                    severity=match.severity,  # type: ignore[arg-type]
                    location=source_location,
                    evidence=f"rule_id={match.rule_id}; source={source_label}; match_count={match.match_count}; sample={match.sample}",
                    verified=True,
                    recommendation=match.recommendation,
                ),
                category=match.category,
                consumers=match.consumers,
            )
        )
    findings.extend(_extract_source_intelligence_findings(source_label=source_label, source_location=source_location, text=text))
    return findings


def _extract_source_intelligence_findings(source_label: str, source_location: str, text: str) -> list[Finding]:
    findings: list[Finding] = []

    api_paths = _unique_preserve_order(match.group(1) for match in API_PATH_RE.finditer(text))
    if api_paths:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered API or route references from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered route hints from {source_label}: {', '.join(api_paths[:5])}",
                verified=True,
                recommendation="Review whether these recovered routes map to reachable application endpoints for follow-up analysis in other modules.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )

    auth_paths = _unique_preserve_order(match.group(1) for match in AUTH_PATH_RE.finditer(text))
    auth_paths = [path for path in auth_paths if "/" in path or path.lower().startswith(("login", "admin", "signin", "signup", "auth"))]
    if auth_paths:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered authentication or admin entrypoint hint from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered auth/admin path hints from {source_label}: {', '.join(auth_paths[:5])}",
                verified=True,
                recommendation="Review whether these recovered auth or admin paths are still reachable and should inform authorized follow-up testing.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "poc"),
            )
        )

    js_assets = _unique_preserve_order(match.group(1) for match in JS_ASSET_RE.finditer(text))
    if js_assets:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered JavaScript asset reference from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered JS asset hints from {source_label}: {', '.join(js_assets[:5])}",
                verified=True,
                recommendation="Use recovered JS asset references to guide follow-up frontend analysis where authorized.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "js"),
            )
        )

    internal_urls = _unique_preserve_order(match.group(0) for match in INTERNAL_URL_RE.finditer(text))
    if internal_urls:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered internal service URL from backup",
                severity="medium",
                location=source_location,
                evidence=f"Recovered internal or private-network URL hints from {source_label}: {', '.join(internal_urls[:4])}",
                verified=True,
                recommendation="Review whether leaked internal service URLs expose topology or follow-up targets for authorized downstream analysis.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "poc"),
            )
        )

    db_hosts = _unique_preserve_order(match.group(1) for match in DB_HOST_ASSIGN_RE.finditer(text))
    db_hosts.extend(host for host in _unique_preserve_order(match.group(1) for match in DATABASE_URL_HOST_RE.finditer(text)) if host not in db_hosts)
    if db_hosts:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered database host hint from backup",
                severity="medium",
                location=source_location,
                evidence=f"Recovered database or service host hints from {source_label}: {', '.join(db_hosts[:4])}",
                verified=True,
                recommendation="Use leaked database host hints only within authorized scope and rotate credentials if the configuration is still valid.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "poc"),
            )
        )

    framework_routes = _extract_framework_route_hints(text)
    if framework_routes:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered framework route definition hint from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered framework route hints from {source_label}: {', '.join(framework_routes[:5])}",
                verified=True,
                recommendation="Use recovered framework route definitions to keep bounded follow-up focused on likely reachable application endpoints.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )

    route_prefixes = _extract_route_prefix_hints(text)
    if route_prefixes:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered route prefix hint from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered route prefix hints from {source_label}: {', '.join(route_prefixes[:5])}",
                verified=True,
                recommendation="Use recovered route prefixes to keep bounded follow-up focused on likely deployment entrypoints and grouped route surfaces.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )

    controller_hints = _extract_controller_hints(text)
    if controller_hints:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered controller or handler hint from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered controller or handler hints from {source_label}: {', '.join(controller_hints[:5])}",
                verified=True,
                recommendation="Use recovered controller names only to bound follow-up around likely auth, admin, export, and API handling code paths.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )

    download_export_hints = _extract_download_export_hints(text)
    if download_export_hints:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered download or export entrypoint hint from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered download/export path hints from {source_label}: {', '.join(download_export_hints[:5])}",
                verified=True,
                recommendation="Use recovered download or export entrypoints to prioritize bounded review of potentially high-value file disclosure or artifact-generation paths.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "poc"),
            )
        )

    upload_import_hints = _extract_upload_import_hints(text)
    if upload_import_hints:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered upload or import entrypoint hint from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered upload/import path hints from {source_label}: {', '.join(upload_import_hints[:5])}",
                verified=True,
                recommendation="Use recovered upload or import entrypoints to keep bounded follow-up focused on likely file-ingest surfaces and admin flows.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "js", "poc"),
            )
        )

    middleware_hints = _extract_framework_middleware_hints(text)
    if middleware_hints:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered authentication or middleware guard hint from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered middleware or guard hints from {source_label}: {', '.join(middleware_hints[:5])}",
                verified=True,
                recommendation="Use recovered guard or middleware hints to prioritize bounded review of auth-protected and admin-relevant code paths.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "poc"),
            )
        )

    config_entrypoints = _extract_config_entrypoint_hints(text)
    if config_entrypoints:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered config-defined entrypoint hint from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered config-defined entrypoint hints from {source_label}: {', '.join(config_entrypoints[:5])}",
                verified=True,
                recommendation="Use recovered config-defined entrypoints to keep bounded discovery near likely deployed path prefixes and auth surfaces.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )

    artifact_name_hints = _extract_artifact_name_hints(text)
    if artifact_name_hints:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered backup artifact naming hint from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered artifact naming hints from {source_label}: {', '.join(artifact_name_hints[:5])}",
                verified=True,
                recommendation="Use recovered artifact names only for a tiny bounded second-pass check near plausible backup, export, and dump naming patterns.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "poc"),
            )
        )

    include_targets = _extract_include_targets(text)
    if include_targets:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered source include or require path hint from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered include/require path hints from {source_label}: {', '.join(include_targets[:5])}",
                verified=True,
                recommendation="Use recovered include or require targets to guide bounded follow-up review of likely high-value source paths.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js"),
            )
        )

    relation_routes = _unique_preserve_order(
        framework_routes[:5]
        + route_prefixes[:5]
        + config_entrypoints[:5]
        + download_export_hints[:5]
        + upload_import_hints[:5]
        + auth_paths[:5]
        + api_paths[:5]
    )
    sensitive_route_tokens = ("admin", "auth", "login", "signin", "report", "export", "backup", "debug")
    sensitive_routes = [
        item for item in relation_routes if any(token in item.lower() for token in sensitive_route_tokens)
    ]
    sensitive_controllers = [
        item
        for item in controller_hints
        if any(token in item.lower() for token in ("admin", "auth", "login", "report", "export", "backup", "debug"))
    ]
    if sensitive_routes and sensitive_controllers:
        findings.append(
            _annotate_finding(
            Finding(
                title="High-value route-controller relationship recovered from backup",
                severity="medium",
                location=source_location,
                evidence=(
                    f"Recovered high-value route/controller relationship from {source_label}: "
                    f"routes={', '.join(sensitive_routes[:4])}; controllers={', '.join(sensitive_controllers[:4])}"
                ),
                verified=True,
                recommendation="Prioritize bounded follow-up around the recovered privileged or export-oriented routes and their controller handlers.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "poc"),
            )
        )

    if download_export_hints and artifact_name_hints:
        findings.append(
            _annotate_finding(
            Finding(
                title="High-value export-artifact relationship recovered from backup",
                severity="medium",
                location=source_location,
                evidence=(
                    f"Recovered export/artifact relationship from {source_label}: "
                    f"paths={', '.join(download_export_hints[:4])}; artifacts={', '.join(artifact_name_hints[:4])}"
                ),
                verified=True,
                recommendation="Prioritize bounded follow-up around export or download handlers that appear to generate named backup, dump, or archive artifacts.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "poc"),
            )
        )

    relationship_seeds = _derive_relationship_followup_seeds(
        route_prefixes=route_prefixes,
        controller_hints=controller_hints,
        config_entrypoints=config_entrypoints,
        download_export_hints=download_export_hints,
        upload_import_hints=upload_import_hints,
        artifact_name_hints=artifact_name_hints,
        auth_paths=auth_paths,
        api_paths=api_paths,
    )
    if relationship_seeds:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered high-confidence relationship follow-up seed from backup",
                severity="info",
                location=source_location,
                evidence=f"Recovered high-confidence follow-up seeds from combined route/controller/config/artifact relationships in {source_label}: {', '.join(relationship_seeds[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use these relationship-backed seeds before generic structure names when running the tiny bounded second-pass discovery flow.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered structured relationship follow-up item from backup",
                severity="info",
                location=source_location,
                evidence=(
                    f"Recovered structured relationship seed items from {source_label}: "
                    + ", ".join(_format_relationship_followup_item(item) for item in _build_relationship_followup_items(relationship_seeds))
                ),
                verified=True,
                recommendation="Use these structured relationship seed items to keep bounded second-pass follow-up explainable and prioritizable for downstream consumers.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )

    return findings


def _extract_archive_structure_findings(archive_probe: ProbeResult, extracted_files: list[Path]) -> list[Finding]:
    structure = _summarize_archive_structure(extracted_files)
    findings: list[Finding] = []

    if structure.frameworks:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered framework fingerprint from backup",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered framework fingerprints from archive structure: {', '.join(structure.frameworks[:4])}",
                verified=True,
                recommendation="Use recovered framework fingerprints only to guide bounded D-side follow-up and later downstream handoff.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )

    if structure.high_value_paths:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered high-value source path hint from backup",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered high-value source paths from archive structure: {', '.join(structure.high_value_paths[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use recovered source paths to keep deeper review bounded around likely route, controller, and configuration hotspots.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js"),
            )
        )

    if structure.route_prefixes:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered structure-derived route prefix hint from backup",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered route prefixes from archive structure review: {', '.join(structure.route_prefixes[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use recovered route prefixes to keep D-side follow-up bounded around likely deployment namespaces and grouped entrypoints.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )

    if structure.controller_hints:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered structure-derived controller hint from backup",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered controller hints from archive structure review: {', '.join(structure.controller_hints[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use recovered controller hints only to keep deeper D-side review focused on likely request-handling hotspots.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )

    if structure.config_entrypoints:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered structure-derived config entrypoint hint from backup",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered config-defined entrypoints from archive structure review: {', '.join(structure.config_entrypoints[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use recovered config-defined entrypoints to keep bounded discovery near likely deployment paths and admin surfaces.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )

    if structure.download_export_hints:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered structure-derived download or export hint from backup",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered download/export hints from archive structure review: {', '.join(structure.download_export_hints[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use recovered download or export hints to keep D-side review bounded around likely artifact-generation and file-disclosure paths.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "poc"),
            )
        )

    if structure.upload_import_hints:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered structure-derived upload or import hint from backup",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered upload/import hints from archive structure review: {', '.join(structure.upload_import_hints[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use recovered upload or import hints to keep D-side follow-up bounded around likely file-ingest surfaces.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "js", "poc"),
            )
        )

    if structure.artifact_name_hints:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered structure-derived artifact naming hint from backup",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered artifact naming hints from archive structure review: {', '.join(structure.artifact_name_hints[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use recovered artifact naming hints only for very small bounded candidate generation near plausible export and backup names.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "poc"),
            )
        )

    if structure.discovery_seeds:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered bounded backup follow-up seed from archive structure",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered bounded discovery seeds from archive structure: {', '.join(structure.discovery_seeds[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use these recovered structure seeds only for a small bounded second-pass backup check, not for recursive crawling.",
            ),
            category="followup_hint",
            consumers=("orchestrator",),
            )
        )

    if structure.correlated_seeds:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered correlated backup follow-up seed from source relationships",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered correlated discovery seeds from route/controller/config relationships: {', '.join(structure.correlated_seeds[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use these correlated seeds first for bounded second-pass backup checks because they were supported by multiple recovered source signal families.",
            ),
            category="followup_hint",
            consumers=("orchestrator",),
            )
        )

    if structure.relationship_seeds:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered structure-derived relationship follow-up seed from backup",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered high-confidence relationship seeds from archive structure review: {', '.join(structure.relationship_seeds[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use these structure-derived relationship seeds before generic structure names during bounded second-pass candidate generation.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered structured structure-derived relationship item from backup",
                severity="info",
                location=archive_probe.url,
                evidence=(
                    "Recovered structured relationship seed items from archive structure review: "
                    + ", ".join(_format_relationship_followup_item(item) for item in structure.relationship_seed_items[:MAX_STRUCTURE_HINTS])
                ),
                verified=True,
                recommendation="Use these structured structure-derived relationship items when explaining why a bounded second-pass candidate stayed in the final small batch.",
            ),
            category="followup_hint",
            consumers=("orchestrator", "sql", "js", "poc"),
            )
        )

    if structure.framework_route_seeds:
        findings.append(
            _annotate_finding(
            Finding(
                title="Recovered route-derived backup follow-up seed from backup",
                severity="info",
                location=archive_probe.url,
                evidence=f"Recovered route-derived discovery seeds from archive content: {', '.join(structure.framework_route_seeds[:MAX_STRUCTURE_HINTS])}",
                verified=True,
                recommendation="Use route-derived seeds only for small bounded follow-up candidate generation that stays near likely deployment naming patterns.",
            ),
            category="followup_hint",
            consumers=("orchestrator",),
            )
        )

    return findings


def _extract_include_targets(text: str) -> list[str]:
    pattern = re.compile(r"(?i)\b(?:include|require|include_once|require_once|from|import)\b\s*(?:\(|)\s*['\"]([^'\"]{2,120})['\"]")
    candidates = _unique_preserve_order(match.group(1) for match in pattern.finditer(text))
    return [item for item in candidates if "/" in item or "." in item][:5]


def _extract_framework_route_hints(text: str) -> list[str]:
    routes: list[str] = []
    for match in FRAMEWORK_ROUTE_RE.finditer(text):
        for group in match.groups():
            if not group:
                continue
            item = group.strip()
            if item.startswith("/"):
                routes.append(item)
    return _unique_preserve_order(routes)[:5]


def _extract_framework_middleware_hints(text: str) -> list[str]:
    return _unique_preserve_order(match.group(0).strip() for match in FRAMEWORK_MIDDLEWARE_RE.finditer(text))[:5]


def _extract_route_prefix_hints(text: str) -> list[str]:
    hints: list[str] = []
    for match in ROUTE_PREFIX_RE.finditer(text):
        for group in match.groups():
            if not group:
                continue
            item = group.strip()
            if not item:
                continue
            if not item.startswith("/"):
                item = f"/{item.lstrip('/')}"
            hints.append(item)
    return _unique_preserve_order(hints)[:5]


def _extract_controller_hints(text: str) -> list[str]:
    controllers = _unique_preserve_order(match.group(1) for match in CONTROLLER_HINT_RE.finditer(text))
    return controllers[:5]


def _extract_download_export_hints(text: str) -> list[str]:
    hints = _unique_preserve_order(match.group(1) for match in DOWNLOAD_EXPORT_PATH_RE.finditer(text))
    return _normalize_path_hint_values(hints)


def _extract_upload_import_hints(text: str) -> list[str]:
    hints = _unique_preserve_order(match.group(1) for match in UPLOAD_IMPORT_PATH_RE.finditer(text))
    return _normalize_path_hint_values(hints)


def _extract_artifact_name_hints(text: str) -> list[str]:
    hints = _unique_preserve_order(match.group(1) for match in ARTIFACT_NAME_HINT_RE.finditer(text))
    return hints[:5]


def _extract_config_entrypoint_hints(text: str) -> list[str]:
    hints = _unique_preserve_order(match.group(1) for match in CONFIG_ENTRYPOINT_RE.finditer(text))
    return _normalize_path_hint_values(hints)


def _normalize_path_hint_values(values: list[str]) -> list[str]:
    normalized: list[str] = []
    for item in values:
        cleaned = item.strip()
        if not cleaned:
            continue
        if cleaned.startswith(("http://", "https://")):
            normalized.append(cleaned)
            continue
        if not cleaned.startswith("/"):
            cleaned = f"/{cleaned.lstrip('/')}"
        normalized.append(cleaned)
    return _unique_preserve_order(normalized)[:5]


def _detect_framework_fingerprints(relative_paths: list[str]) -> list[str]:
    lowered_paths = [path.lower() for path in relative_paths]
    frameworks: list[str] = []
    for framework, markers in FRAMEWORK_PATH_SIGNATURES:
        if any(marker in path for marker in markers for path in lowered_paths):
            frameworks.append(framework)
    return frameworks


def _extract_high_value_source_paths(relative_paths: list[str]) -> list[str]:
    hints: list[str] = []
    for path in relative_paths:
        lowered = path.lower()
        if any(marker in lowered for marker in HIGH_VALUE_SOURCE_PATH_MARKERS):
            hints.append(path)
    return _unique_preserve_order(hints)[:MAX_STRUCTURE_HINTS]


def _derive_structure_followup_seeds(
    relative_paths: list[str],
    frameworks: list[str],
    route_seeds: list[str],
    framework_route_seeds: list[str],
    correlated_seeds: list[str],
    relationship_seeds: list[str],
    controller_hints: list[str],
    artifact_name_hints: list[str],
) -> list[str]:
    seeds: list[str] = []
    framework_defaults = {
        "laravel": ["routes", "storage", "bootstrap", "artisan"],
        "django": ["settings", "urls", "manage"],
        "spring": ["application", "bootstrap", "pom"],
        "wordpress": ["wp-config", "wp-content"],
        "thinkphp": ["route", "config", "database"],
    }
    for framework in frameworks:
        seeds.extend(framework_defaults.get(framework, []))
    seeds.extend(correlated_seeds)
    seeds.extend(relationship_seeds)
    seeds.extend(framework_route_seeds)
    seeds.extend(route_seeds)
    seeds.extend(_normalize_controller_seed(controller) for controller in controller_hints)
    seeds.extend(_normalize_artifact_seed(name) for name in artifact_name_hints)

    for path in relative_paths:
        posix = PurePosixPath(path)
        parts = [part for part in posix.parts if part not in {".", ".."}]
        if not parts:
            continue
        stem_seed = _normalize_dynamic_seed(posix.stem)
        if stem_seed and stem_seed not in GENERIC_PATH_SEGMENTS:
            seeds.append(stem_seed)
        for part in parts[-2:]:
            cleaned = _normalize_dynamic_seed(part)
            if cleaned and cleaned not in GENERIC_PATH_SEGMENTS:
                seeds.append(cleaned)

    return _unique_preserve_order(seeds)[:MAX_STRUCTURE_FOLLOWUP_CANDIDATES]


def _prioritize_structure_followup_seeds(structure: ArchiveStructureSummary) -> list[str]:
    high_signal = _unique_preserve_order(
        structure.correlated_seeds
        + structure.relationship_seeds
        + [_normalize_artifact_seed(name) for name in structure.artifact_name_hints]
        + [_normalize_controller_seed(name) for name in structure.controller_hints]
        + structure.framework_route_seeds
    )
    high_signal = [seed for seed in high_signal if seed]
    prioritized: list[str] = []
    for seed in high_signal:
        if seed not in prioritized:
            prioritized.append(seed)

    for seed in structure.discovery_seeds:
        if seed in prioritized:
            continue
        if high_signal and seed in GENERIC_STRUCTURE_SEEDS and _is_shadowed_generic_structure_seed(seed, high_signal):
            continue
        if high_signal and seed in GENERIC_STRUCTURE_SEEDS and len(prioritized) >= max(2, MAX_STRUCTURE_FOLLOWUP_CANDIDATES // 2 - 1):
            continue
        prioritized.append(seed)

    return prioritized[:MAX_STRUCTURE_FOLLOWUP_CANDIDATES]


def _structure_seed_inference_source(seed: str, structure: ArchiveStructureSummary) -> str:
    if seed in structure.correlated_seeds:
        return "correlated_seed"
    if seed in structure.relationship_seeds:
        return "relationship_seed"
    if seed in structure.framework_route_seeds:
        return "framework_route_seed"
    normalized_artifact_seeds = {_normalize_artifact_seed(name) for name in structure.artifact_name_hints}
    if seed in normalized_artifact_seeds:
        return "artifact_name_seed"
    normalized_controller_seeds = {_normalize_controller_seed(name) for name in structure.controller_hints}
    if seed in normalized_controller_seeds:
        return "controller_seed"
    if seed in structure.route_seeds:
        return "route_path_seed"
    return "generic_structure_seed"


def _is_shadowed_generic_structure_seed(seed: str, high_signal: list[str]) -> bool:
    for signal in high_signal:
        if signal == seed:
            continue
        parts = [part for part in re.split(r"[-_]+", signal) if part]
        if seed in parts:
            return True
        if signal.startswith(f"{seed}-") or signal.endswith(f"-{seed}"):
            return True
    return False


def _collect_structure_relationship_hints(
    extracted_files: list[Path],
) -> tuple[list[str], list[str], list[str], list[str], list[str], list[str]]:
    route_prefixes: list[str] = []
    controller_hints: list[str] = []
    config_entrypoints: list[str] = []
    download_export_hints: list[str] = []
    upload_import_hints: list[str] = []
    artifact_name_hints: list[str] = []
    for file_path in extracted_files[:MAX_AUDIT_FILES]:
        if not _looks_textual(file_path):
            continue
        text = read_text_preview(file_path)
        route_prefixes.extend(_extract_route_prefix_hints(text))
        controller_hints.extend(_extract_controller_hints(text))
        config_entrypoints.extend(_extract_config_entrypoint_hints(text))
        download_export_hints.extend(_extract_download_export_hints(text))
        upload_import_hints.extend(_extract_upload_import_hints(text))
        artifact_name_hints.extend(_extract_artifact_name_hints(text))
    return (
        _unique_preserve_order(route_prefixes)[:MAX_STRUCTURE_HINTS],
        _unique_preserve_order(controller_hints)[:MAX_STRUCTURE_HINTS],
        _unique_preserve_order(config_entrypoints)[:MAX_STRUCTURE_HINTS],
        _unique_preserve_order(download_export_hints)[:MAX_STRUCTURE_HINTS],
        _unique_preserve_order(upload_import_hints)[:MAX_STRUCTURE_HINTS],
        _unique_preserve_order(artifact_name_hints)[:MAX_STRUCTURE_HINTS],
    )


def _derive_correlated_discovery_seeds(
    framework_route_seeds: list[str],
    route_prefixes: list[str],
    controller_hints: list[str],
    config_entrypoints: list[str],
    download_export_hints: list[str],
    artifact_name_hints: list[str],
    relationship_seeds: list[str],
) -> list[str]:
    seed_families: dict[str, set[str]] = {}

    def add_family(family: str, seeds: list[str]) -> None:
        for seed in seeds:
            normalized = seed.strip()
            if not normalized:
                continue
            seed_families.setdefault(normalized, set()).add(family)

    route_prefix_seeds: list[str] = []
    for item in route_prefixes:
        route_prefix_seeds.extend(_normalize_route_seed(item))

    config_entry_seeds: list[str] = []
    for item in config_entrypoints:
        config_entry_seeds.extend(_normalize_route_seed(item))

    controller_seeds = [
        normalized
        for normalized in (_normalize_controller_seed(controller) for controller in controller_hints)
        if normalized
    ]
    download_export_seeds: list[str] = []
    for item in download_export_hints:
        download_export_seeds.extend(_normalize_route_seed(item))
    artifact_seeds = [
        normalized
        for normalized in (_normalize_artifact_seed(name) for name in artifact_name_hints)
        if normalized
    ]

    add_family("framework_route", framework_route_seeds)
    add_family("route_prefix", _unique_preserve_order(route_prefix_seeds))
    add_family("config_entry", _unique_preserve_order(config_entry_seeds))
    add_family("controller", controller_seeds)
    add_family("download_export", _unique_preserve_order(download_export_seeds))
    add_family("artifact_name", artifact_seeds)
    add_family("relationship", relationship_seeds)

    ranked = sorted(
        (
            (seed, families)
            for seed, families in seed_families.items()
            if len(families) >= 2
        ),
        key=lambda item: (-len(item[1]), "-" not in item[0], item[0]),
    )
    return [seed for seed, _families in ranked[:MAX_CORRELATED_DISCOVERY_SEEDS]]


def _derive_relationship_followup_seeds(
    *,
    route_prefixes: list[str],
    controller_hints: list[str],
    config_entrypoints: list[str],
    download_export_hints: list[str],
    upload_import_hints: list[str],
    artifact_name_hints: list[str],
    auth_paths: list[str] | None = None,
    api_paths: list[str] | None = None,
) -> list[str]:
    route_seed_bases: list[str] = []
    for item in route_prefixes + config_entrypoints + download_export_hints + (auth_paths or []) + (api_paths or []):
        route_seed_bases.extend(_normalize_route_seed(item))
    route_seed_bases = [
        seed for seed in _unique_preserve_order(route_seed_bases)
        if seed and (seed not in GENERIC_STRUCTURE_SEEDS or seed in {"admin", "auth"})
    ]
    controller_seeds = [
        seed
        for seed in (_normalize_controller_seed(controller) for controller in controller_hints)
        if seed and (seed not in GENERIC_STRUCTURE_SEEDS or seed in {"admin", "auth"})
    ]
    artifact_seeds = [
        seed
        for seed in (_normalize_artifact_seed(name) for name in artifact_name_hints)
        if seed and seed not in GENERIC_STRUCTURE_SEEDS
    ]
    upload_seeds: list[str] = []
    for item in upload_import_hints:
        upload_seeds.extend(_normalize_route_seed(item))
    upload_seeds = [
        seed for seed in _unique_preserve_order(upload_seeds)
        if seed and (seed not in GENERIC_STRUCTURE_SEEDS or seed in {"admin", "auth"})
    ]

    combined: list[str] = []
    for route_seed in route_seed_bases[:4]:
        for controller_seed in controller_seeds[:3]:
            combined.append(_combine_seed_pair(route_seed, controller_seed))
        for artifact_seed in artifact_seeds[:3]:
            combined.append(_combine_seed_pair(route_seed, artifact_seed))
    for upload_seed in upload_seeds[:3]:
        for controller_seed in controller_seeds[:3]:
            combined.append(_combine_seed_pair(upload_seed, controller_seed))
    if artifact_seeds and controller_seeds:
        combined.append(_combine_seed_pair(artifact_seeds[0], controller_seeds[0]))
    ranked = sorted(
        (seed for seed in _unique_preserve_order(combined) if seed),
        key=_relationship_seed_sort_key,
    )
    if any(_relationship_seed_has_privileged_component(seed) for seed in ranked):
        ranked = [
            seed
            for seed in ranked
            if _relationship_seed_has_privileged_component(seed) or _relationship_seed_has_operational_component(seed)
        ]
    selected: list[str] = []
    seen_signatures: set[tuple[str, str]] = set()
    for seed in ranked:
        signature = _relationship_seed_signature(seed)
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        selected.append(seed)
        if len(selected) >= MAX_STRUCTURE_HINTS:
            break
    return selected


def _combine_seed_pair(left: str, right: str) -> str:
    left_clean = _normalize_relationship_seed_component(left, keep_compound=True)
    right_clean = _normalize_relationship_seed_component(right, keep_compound=False)
    if not left_clean or not right_clean or left_clean == right_clean:
        return ""
    if (left_clean in GENERIC_STRUCTURE_SEEDS and left_clean not in {"admin", "auth"}) or (
        right_clean in GENERIC_STRUCTURE_SEEDS and right_clean not in {"admin", "auth"}
    ):
        return ""
    left_parts = [part for part in re.split(r"[-_]+", left_clean) if part]
    if any(_seed_stem(part) == _seed_stem(right_clean) for part in left_parts):
        return ""
    return f"{left_clean}-{right_clean}"


def _normalize_relationship_seed_component(value: str, *, keep_compound: bool) -> str:
    normalized = _normalize_dynamic_seed(value)
    if not normalized:
        return ""
    parts = [part for part in re.split(r"[-_]+", normalized) if part]
    cleaned_parts: list[str] = []
    for part in parts:
        token = re.sub(r"(?:tar|tgz|zip|rar|sql|bak|gzip)+$", "", part)
        token = _normalize_dynamic_seed(token)
        if not token:
            continue
        if (token in GENERIC_STRUCTURE_SEEDS and token not in {"admin", "auth"}) or token in GENERIC_RELATIONSHIP_COMPONENTS:
            continue
        cleaned_parts.append(token)
    if not cleaned_parts:
        cleaned_parts = [part for part in parts if part not in GENERIC_STRUCTURE_SEEDS]
    if not cleaned_parts:
        return ""
    if keep_compound:
        return "-".join(cleaned_parts[:2])
    return cleaned_parts[0]


def _relationship_seed_sort_key(seed: str) -> tuple[int, int, int, str]:
    parts = [part for part in re.split(r"[-_]+", seed) if part]
    privileged_score = sum(part in {"admin", "auth", "login", "signin", "debug", "backup"} for part in parts)
    operational_score = sum(part in {"report", "reports", "export", "upload", "import"} for part in parts)
    priority_component_score = sum(part in RELATIONSHIP_PRIORITY_COMPONENTS for part in parts)
    return (-privileged_score, -operational_score, -priority_component_score, len(parts), seed)


def _relationship_seed_has_privileged_component(seed: str) -> bool:
    parts = [part for part in re.split(r"[-_]+", seed) if part]
    return any(part in {"admin", "auth", "login", "signin", "debug", "backup"} for part in parts)


def _relationship_seed_has_operational_component(seed: str) -> bool:
    parts = [part for part in re.split(r"[-_]+", seed) if part]
    return any(part in {"report", "reports", "export", "upload", "import"} for part in parts)


def _seed_stem(value: str) -> str:
    cleaned = value.strip().lower()
    if len(cleaned) > 4 and cleaned.endswith("ies"):
        return f"{cleaned[:-3]}y"
    if len(cleaned) > 4 and cleaned.endswith("es"):
        return cleaned[:-2]
    if len(cleaned) > 3 and cleaned.endswith("s"):
        return cleaned[:-1]
    return cleaned


def _relationship_seed_signature(seed: str) -> tuple[str, str]:
    parts = [part for part in re.split(r"[-_]+", seed) if part]
    if not parts:
        return ("", "")
    if len(parts) == 1:
        stem = _seed_stem(parts[0])
        return (stem, stem)
    return (_seed_stem(parts[0]), _seed_stem(parts[1]))


def _build_relationship_followup_items(seeds: list[str]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for seed in seeds[:MAX_STRUCTURE_HINTS]:
        parts = [part for part in re.split(r"[-_]+", seed) if part]
        privileged = _relationship_seed_has_privileged_component(seed)
        operational = _relationship_seed_has_operational_component(seed)
        if privileged and operational:
            priority = "high"
        elif privileged or operational:
            priority = "medium"
        else:
            priority = "low"
        traits: list[str] = []
        if privileged:
            traits.append("privileged")
        if operational:
            traits.append("operational")
        if not traits:
            traits.append("generic")
        items.append(
            {
                "seed": seed,
                "priority": priority,
                "traits": "|".join(traits),
                "components": "|".join(parts[:2]) if parts else seed,
            }
        )
    return items


def _format_relationship_followup_item(item: dict[str, str]) -> str:
    return (
        f"{item.get('seed', '')}:"
        f"{item.get('priority', 'low')}:"
        f"{item.get('traits', 'generic')}:"
        f"{item.get('components', '')}"
    )


def _archive_retry_profile_for_outcome(outcome: str) -> dict[str, str]:
    if outcome == "missing_optional_unpacker":
        return {
            "retry_class": "environment_retry",
            "retry_readiness": "actionable",
            "retry_ready_now": "true",
            "retry_prerequisites": "optional_unpacker_support",
            "retry_requires_new_input": "false",
            "retry_blocked_by_policy": "false",
            "next_step": "validate_optional_unpacker_support_then_retry",
        }
    if outcome in {"password_attempts_exhausted", "password_candidates_unavailable"}:
        return {
            "retry_class": "credential_retry",
            "retry_readiness": "deferred",
            "retry_ready_now": "false",
            "retry_prerequisites": "authorized_password_material",
            "retry_requires_new_input": "true",
            "retry_blocked_by_policy": "false",
            "next_step": "retry_only_with_new_authorized_password_material",
        }
    if outcome == "password_strategy_unsupported":
        return {
            "retry_class": "policy_boundary",
            "retry_readiness": "policy_blocked",
            "retry_ready_now": "false",
            "retry_prerequisites": "manual_review_only",
            "retry_requires_new_input": "false",
            "retry_blocked_by_policy": "true",
            "next_step": "respect_format_boundary_and_require_manual_review",
        }
    return {
        "retry_class": "manual_review",
        "retry_readiness": "manual_only",
        "retry_ready_now": "false",
        "retry_prerequisites": "manual_archive_review",
        "retry_requires_new_input": "true",
        "retry_blocked_by_policy": "false",
        "next_step": "review_archive_access_and_authorized_password_material_manually",
    }


def _archive_retry_evidence_fields(profile: dict[str, str]) -> str:
    return "; ".join(
        (
            f"retry_class={profile['retry_class']}",
            f"retry_readiness={profile['retry_readiness']}",
            f"retry_ready_now={profile['retry_ready_now']}",
            f"retry_prerequisites={profile['retry_prerequisites']}",
            f"retry_requires_new_input={profile['retry_requires_new_input']}",
            f"retry_blocked_by_policy={profile['retry_blocked_by_policy']}",
            f"next_step={profile['next_step']}",
        )
    )


def _derive_route_like_seeds_from_paths(relative_paths: list[str]) -> list[str]:
    seeds: list[str] = []
    routeish_markers = {"routes", "route", "controller", "controllers", "admin", "auth", "api"}
    for path in relative_paths:
        posix = PurePosixPath(path)
        for part in posix.parts:
            cleaned = _normalize_dynamic_seed(part)
            if cleaned and cleaned in routeish_markers:
                seeds.append(cleaned)
        stem_seed = _normalize_dynamic_seed(posix.stem)
        if stem_seed and any(marker in stem_seed for marker in ("admin", "auth", "api", "route")):
            seeds.append(stem_seed)
    return _unique_preserve_order(seeds)[:MAX_STRUCTURE_HINTS]


def _derive_route_like_seeds_from_text(extracted_files: list[Path]) -> list[str]:
    seeds: list[str] = []
    for file_path in extracted_files[:MAX_AUDIT_FILES]:
        if not _looks_textual(file_path):
            continue
        text = read_text_preview(file_path)
        for route in _extract_framework_route_hints(text):
            normalized = _normalize_route_seed(route)
            if normalized:
                seeds.extend(normalized)
        for middleware_hint in _extract_framework_middleware_hints(text):
            for token in ("auth", "admin", "api"):
                if token in middleware_hint.lower():
                    seeds.append(token)
    ordered = _unique_preserve_order(seeds)
    prioritized = [seed for seed in ordered if "-" in seed] + [seed for seed in ordered if "-" not in seed]
    return prioritized[:MAX_STRUCTURE_HINTS]


def _normalize_route_seed(route: str) -> list[str]:
    cleaned = route.strip().strip("/")
    if not cleaned:
        return []
    parts = [re.sub(r"[^a-z0-9_-]+", "", segment.lower()) for segment in cleaned.split("/") if segment.strip()]
    parts = [part for part in parts if len(part) >= 3]
    seeds: list[str] = []
    if parts:
        seeds.append("-".join(parts[:2]))
        seeds.append(parts[-1])
        if len(parts) > 1:
            seeds.append(parts[0])
    return _unique_preserve_order(seeds)


def _normalize_controller_seed(controller: str) -> str:
    lowered = controller.strip()
    lowered = re.sub(r"(?i)(controller|handler|viewset|apiview)$", "", lowered)
    return _normalize_dynamic_seed(lowered)


def _normalize_artifact_seed(name: str) -> str:
    base = name.strip().lower()
    base = re.sub(r"\.(?:tar\.gz|tgz|zip|7z|rar|sql|bak)$", "", base)
    base = base.replace(".", "-")
    parts = [part for part in re.split(r"[-_]+", base) if len(part) >= 3]
    if not parts:
        return _normalize_dynamic_seed(base)
    prioritized = [part for part in parts if part not in {"backup", "archive", "dump", "export"}]
    candidate = prioritized[0] if prioritized else parts[0]
    return _normalize_dynamic_seed(candidate)


def _looks_textual(path: Path) -> bool:
    lowered = path.name.lower()
    if lowered.endswith(TEXT_EXTENSIONS):
        return True
    if lowered in KEY_FILENAMES:
        return True
    try:
        sample = path.read_bytes()[:512]
    except OSError:
        return False
    if not sample:
        return True
    return b"\x00" not in sample


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    deduped: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        key = (finding.title, finding.location, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _unique_preserve_order(values) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        item = value.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _annotate_finding(finding: Finding, *, category: str, consumers: tuple[str, ...]) -> Finding:
    prefix = f"[category={category}][consumers={','.join(consumers)}]"
    finding.evidence = f"{prefix} {finding.evidence}".strip()
    finding.metadata["backup_category"] = category
    finding.metadata["backup_consumers"] = list(consumers)
    if category == "checklist":
        finding.kind = "scope"
        finding.verification_status = "informational"
        finding.verified = False
    elif category == "followup_hint":
        finding.kind = "scope"
        finding.verification_status = "informational"
        finding.verified = False
    elif category == "artifact_download":
        finding.kind = "evidence"
        finding.verification_status = "informational"
        finding.verified = False
    elif category == "archive_extracted":
        finding.kind = "evidence"
        finding.verification_status = "confirmed"
        finding.verified = True
    elif category == "archive_followup":
        finding.kind = "evidence"
        finding.verification_status = "manual_required"
        finding.verified = False
    elif category == "exposure":
        if "HTTP 200" in finding.evidence or "HTTP 206" in finding.evidence:
            finding.kind = "vulnerability"
            finding.verification_status = "confirmed"
            finding.verified = True
        else:
            finding.kind = "candidate"
            finding.verification_status = "unconfirmed"
            finding.verified = False
    elif category == "weak_archive_password":
        finding.kind = "vulnerability"
        finding.verification_status = "confirmed"
        finding.verified = True
    return finding


def run_backup_audit_extended(target_url: str) -> ModuleResult:
    started = now_iso()
    if not is_local_or_lab_target(target_url):
        result = ModuleResult(
            module="backup_audit_extended",
            target=target_url,
            status="skipped",
            findings=[],
            logs=["Target is outside the local/course-lab allowlist; backup audit skipped."],
            started_at=started,
            finished_at=now_iso(),
            error="only localhost or course lab targets are allowed",
        )
        result.validate()
        return result

    workspace: Path | None = None
    try:
        logs = [
            "Checking an allowlisted, read-only backup filename dictionary.",
            f"Download and extraction guards: max_download_bytes={MAX_DOWNLOAD_BYTES}, max_download_count={MAX_DOWNLOAD_COUNT}.",
            "Archive handlers: built-in zip/tar support enabled; patool fallback will be used when available for other formats.",
        ]
        entrypoint_probe = fetch_text(target_url, timeout=0.4, max_bytes=8192)
        if not entrypoint_probe.ok and entrypoint_probe.status_code == 0:
            logs.append(f"Target entrypoint is unavailable; bounded backup probing stopped early: {entrypoint_probe.error}")
            result = ModuleResult(
                module="backup_audit_extended",
                target=target_url,
                status="ok",
                findings=[
                    _annotate_finding(
                        Finding(
                            title="Backup filename risk checklist",
                            severity="medium",
                            location="backup.zip / www.zip / web.zip / db.sql / .env / .git/config",
                            evidence="Target entrypoint was unavailable during the short read-only probe; keep backup exposure review as a release checklist item.",
                            verified=False,
                            recommendation="Bring the target online first, then verify that the web root does not expose source bundles, database exports, temp files, or environment configs.",
                        ),
                        category="checklist",
                        consumers=("orchestrator",),
                    )
                ],
                logs=logs,
                started_at=started,
                finished_at=now_iso(),
            )
            result.validate()
            return result
        dynamic_candidates = _infer_dynamic_candidates(target_url)
        all_candidates = list(BACKUP_CANDIDATES) + dynamic_candidates
        if dynamic_candidates:
            logs.append(
                "Generated bounded dynamic backup candidates: "
                + ", ".join(candidate.path for candidate in dynamic_candidates[:6])
            )
        probe_results = _probe_paths_batch(target_url, all_candidates)
        metadata_followup = _build_metadata_followup_candidates(
            probe_results,
            {item.candidate.path for item in probe_results},
        )
        if metadata_followup:
            logs.append(
                "Generated bounded metadata-derived follow-up candidates: "
                + ", ".join(candidate.path for candidate in metadata_followup[:6])
            )
            probe_results.extend(_probe_paths_batch(target_url, metadata_followup))
        exposed = [item for item in probe_results if item.accessible]
        confirmed_exposed = [item for item in exposed if _is_confirmed_exposure(item)]
        missed = [item for item in probe_results if not item.accessible and item.status_code in {401, 404}]
        uncertain = [item for item in probe_results if not item.accessible and item.status_code not in {0, 401, 404}]
        failures = [item for item in probe_results if not item.accessible and item.status_code == 0 and item.error]

        logs.append(
            f"Checked {len(probe_results)} candidates: exposed={len(exposed)}, confirmed_exposed={len(confirmed_exposed)}, missed={len(missed)}, uncertain={len(uncertain)}, failed={len(failures)}."
        )
        for item in uncertain[:5]:
            logs.append(f"Uncertain response: {item.candidate.path} -> HTTP {item.status_code}")
        for item in failures[:5]:
            logs.append(f"Probe failed: {item.candidate.path} -> {item.error}")

        findings: list[Finding] = _exposure_findings_from_results(exposed)

        download_targets = [item for item in confirmed_exposed if _should_download(item)][:MAX_DOWNLOAD_COUNT]
        probed_candidate_paths = {item.candidate.path for item in probe_results}
        if download_targets:
            workspace = create_temp_workspace()
            logs.append(f"Created temporary workspace for bounded backup handling: {workspace}")

        structure_followup_exposed: list[ProbeResult] = []
        for item in download_targets:
            artifact, error = _download_candidate(item, workspace)  # type: ignore[arg-type]
            if artifact is None:
                logs.append(f"Download skipped or failed for {item.candidate.path}: {error}")
                continue
            findings.append(_build_download_finding(artifact))

            if artifact.is_archive:
                extract_root = workspace / f"extract_{artifact.saved_path.stem}"  # type: ignore[operator]
                controlled_passwords = _build_controlled_password_candidates(artifact, target_url)
                extracted = extract_archive(
                    artifact.saved_path,
                    extract_root,
                    password_candidates=controlled_passwords,
                )
                attempted_passwords = list(getattr(extracted, "attempted_passwords", []))
                password_strategy = getattr(extracted, "password_strategy", "")
                outcome_code = getattr(extracted, "outcome_code", "")
                archive_type = getattr(extracted, "archive_type", "") or artifact.saved_path.suffix.lower().lstrip(".")
                password_attempt_count = int(getattr(extracted, "password_attempt_count", len(attempted_passwords) or len(controlled_passwords)))
                strategy_supported = bool(getattr(extracted, "strategy_supported", False))
                if not extracted.extracted:
                    logs.append(f"Archive extraction failed for {artifact.saved_path.name}: {extracted.error}")
                    if outcome_code == "missing_optional_unpacker":
                        logs.append(f"Optional unpacker is unavailable for {artifact.saved_path.name}; non-zip bounded handling cannot continue in this environment.")
                        findings.append(_build_non_zip_unpacker_gap_finding(artifact, archive_type))
                        continue
                    if extracted.requires_password:
                        if artifact.saved_path.name.lower().endswith(".zip"):
                            findings.append(
                                _build_password_protected_archive_finding(
                                    artifact,
                                    extracted.error,
                                    password_attempt_count=password_attempt_count,
                                )
                            )
                        else:
                            logs.append(
                                f"Protected non-zip archive detected for {artifact.saved_path.name}; attempted bounded password strategy with {password_attempt_count} candidates."
                            )
                            if attempted_passwords:
                                findings.append(
                                    _build_non_zip_password_strategy_finding(
                                        artifact,
                                        archive_type or "patool",
                                        attempted_passwords,
                                    )
                                )
                            if outcome_code == "password_attempts_exhausted":
                                findings.append(_build_non_zip_password_exhausted_finding(artifact, archive_type, password_attempt_count))
                            if outcome_code == "password_strategy_unsupported" or (password_strategy and not strategy_supported):
                                findings.append(_build_non_zip_password_strategy_unsupported_finding(artifact, archive_type))
                            findings.append(
                                _build_non_zip_password_protected_archive_finding(
                                    artifact,
                                    extracted.error,
                                    outcome=outcome_code or "password_required",
                                    archive_type=archive_type,
                                    password_attempt_count=password_attempt_count,
                                    strategy_supported=strategy_supported,
                                )
                            )
                    else:
                        findings.append(_build_archive_extraction_failure_finding(artifact, extracted.error))
                    continue
                if extracted.used_patool:
                    logs.append(f"Archive extraction used patool fallback for {artifact.saved_path.name}.")
                if password_strategy == "controlled_non_zip_password_candidates":
                    findings.append(
                        _build_non_zip_password_strategy_finding(
                            artifact,
                            extracted.archive_type,
                            attempted_passwords,
                        )
                    )
                if extracted.used_weak_password:
                    logs.append(f"Weak password extraction succeeded for {artifact.saved_path.name}.")
                    findings.append(_build_weak_password_archive_finding(artifact, extracted.successful_password))
                logs.append(
                    f"Archive extracted: {artifact.saved_path.name} -> {len(extracted.extracted_files)} files ({extracted.archive_type})."
                )
                findings.append(
                    _annotate_finding(
                    Finding(
                        title="Downloaded archive was successfully extracted for static audit",
                        severity="medium",
                        location=item.url,
                        evidence=f"archive={artifact.saved_path.name}; extracted_files={len(extracted.extracted_files)}; archive_type={extracted.archive_type}",
                        verified=True,
                        recommendation="Treat publicly downloadable archives as a source disclosure event and review their contents.",
                    ),
                    category="archive_extracted",
                    consumers=("orchestrator",),
                    )
                )
                findings.extend(_audit_extracted_files(item, extracted.extracted_files))
                followup_candidates = _build_structure_followup_candidates(extracted.extracted_files, probed_candidate_paths)
                if followup_candidates:
                    logs.append(
                        "Generated bounded structure-derived follow-up candidates: "
                        + ", ".join(candidate.path for candidate in followup_candidates[:6])
                    )
                    followup_probe_results = _probe_paths_batch(target_url, followup_candidates)
                    probed_candidate_paths.update(candidate.path for candidate in followup_candidates)
                    structure_followup_exposed.extend([probe for probe in followup_probe_results if probe.accessible])
            else:
                findings.extend(_audit_artifact(artifact))

        if structure_followup_exposed:
            logs.append(
                f"Second-pass bounded structure follow-up confirmed {len(structure_followup_exposed)} additional exposures."
            )
            findings.extend(_build_structure_followup_exposure_finding(item) for item in structure_followup_exposed)

            extra_downloads = [item for item in structure_followup_exposed if _should_download(item)][:MAX_STRUCTURE_FOLLOWUP_DOWNLOADS]
            for item in extra_downloads:
                if workspace is None:
                    workspace = create_temp_workspace()
                    logs.append(f"Created temporary workspace for bounded backup handling: {workspace}")
                artifact, error = _download_candidate(item, workspace)
                if artifact is None:
                    logs.append(f"Download skipped or failed for structure follow-up {item.candidate.path}: {error}")
                    continue
                findings.append(_build_download_finding(artifact))
                if artifact.is_archive:
                    extract_root = workspace / f"followup_extract_{artifact.saved_path.stem}"  # type: ignore[operator]
                    extracted = extract_archive(artifact.saved_path, extract_root)
                    if extracted.extracted:
                        findings.extend(_audit_extracted_files(item, extracted.extracted_files))
                else:
                    findings.extend(_audit_artifact(artifact))

        if not findings:
            findings = [
                _annotate_finding(
                Finding(
                    title="Backup filename risk checklist",
                    severity="medium",
                    location="backup.zip / www.zip / web.zip / db.sql / .env / .git/config",
                    evidence="No accessible file was confirmed during the short read-only probe; keep this as a release checklist item.",
                    verified=False,
                    recommendation="Verify that the web root does not expose source bundles, database exports, temp files, or environment configs.",
                ),
                category="checklist",
                consumers=("orchestrator",),
                )
            ]

        result = ModuleResult(
            module="backup_audit_extended",
            target=target_url,
            status="ok",
            findings=_deduplicate_findings(findings),
            logs=logs,
            started_at=started,
            finished_at=now_iso(),
        )
        result.validate()
        return result
    except Exception as exc:
        result = ModuleResult(
            module="backup_audit_extended",
            target=target_url,
            status="failed",
            findings=[],
            logs=["Backup audit aborted due to an internal error."],
            started_at=started,
            finished_at=now_iso(),
            error=str(exc),
        )
        result.validate()
        return result
    finally:
        if workspace is not None:
            cleanup_path(workspace)
