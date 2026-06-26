import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

try:
    import patoolib
except ImportError:  # pragma: no cover - optional dependency
    patoolib = None


MAX_EXTRACTED_FILES = 80
MAX_TEXT_PREVIEW_BYTES = 16384


@dataclass(slots=True)
class ExtractionResult:
    extracted: bool
    extracted_files: list[Path]
    archive_type: str = ""
    used_patool: bool = False
    requires_password: bool = False
    used_weak_password: bool = False
    successful_password: str = ""
    password_strategy: str = ""
    attempted_passwords: list[str] = field(default_factory=list)
    password_attempt_count: int = 0
    strategy_supported: bool = False
    outcome_code: str = ""
    error: str = ""


class ArchiveHandlingError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        requires_password: bool = False,
        attempted_passwords: list[str] | None = None,
        password_strategy: str = "",
        archive_type: str = "",
        strategy_supported: bool = False,
        outcome_code: str = "",
    ) -> None:
        super().__init__(message)
        self.requires_password = requires_password
        self.attempted_passwords = list(attempted_passwords or [])
        self.password_strategy = password_strategy
        self.archive_type = archive_type
        self.strategy_supported = strategy_supported
        self.outcome_code = outcome_code


WEAK_PASSWORD_CANDIDATES = (
    "",
    "123456",
    "12345678",
    "password",
    "admin",
    "root",
    "backup",
    "www",
    "web",
)

PATool_PASSWORD_SUPPORTED_SUFFIXES = (".7z", ".rar")


def ensure_directory(path: str) -> Path:
    """
    为后续扩展版保留的目录创建工具。
    当前 D-MVP 主要用于结果落盘或后续下载功能预留。
    """
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def create_temp_workspace(prefix: str = "backup_audit_") -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


def cleanup_path(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def write_bytes(path: Path, content: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def extract_archive(
    archive_path: Path,
    destination: Path,
    max_files: int = MAX_EXTRACTED_FILES,
    password_candidates: list[str] | tuple[str, ...] | None = None,
) -> ExtractionResult:
    destination.mkdir(parents=True, exist_ok=True)
    normalized_candidates = _normalize_password_candidates(password_candidates)
    archive_type = _describe_archive_type(archive_path)

    try:
        if zipfile.is_zipfile(archive_path):
            extracted_files, used_password, attempted_passwords = _extract_zip(
                archive_path,
                destination,
                max_files=max_files,
                password_candidates=normalized_candidates,
            )
            return ExtractionResult(
                extracted=True,
                extracted_files=extracted_files,
                archive_type="zip",
                used_weak_password=bool(used_password),
                successful_password=used_password,
                password_strategy="controlled_weak_password_candidates" if normalized_candidates else "built_in_weak_password_candidates",
                attempted_passwords=attempted_passwords,
                password_attempt_count=len(attempted_passwords),
                strategy_supported=True,
                outcome_code="extracted",
            )
        if tarfile.is_tarfile(archive_path):
            extracted = _extract_tar(archive_path, destination, max_files=max_files)
            return ExtractionResult(extracted=True, extracted_files=extracted, archive_type="tar", outcome_code="extracted")
        if patoolib is not None:
            extracted, used_password, attempted_passwords, strategy = _extract_with_patool(
                archive_path,
                destination,
                max_files=max_files,
                password_candidates=normalized_candidates,
            )
            return ExtractionResult(
                extracted=True,
                extracted_files=extracted,
                archive_type=f"patool:{archive_path.suffix.lower().lstrip('.') or 'archive'}",
                used_patool=True,
                used_weak_password=bool(used_password),
                successful_password=used_password,
                password_strategy=strategy,
                attempted_passwords=attempted_passwords,
                password_attempt_count=len(attempted_passwords),
                strategy_supported=archive_path.suffix.lower() in PATool_PASSWORD_SUPPORTED_SUFFIXES,
                outcome_code="extracted",
            )
        return ExtractionResult(
            extracted=False,
            extracted_files=[],
            archive_type=archive_type,
            outcome_code="missing_optional_unpacker",
            error="optional unpacker unavailable for non-zip archive handling",
        )
    except ArchiveHandlingError as exc:
        return ExtractionResult(
            extracted=False,
            extracted_files=[],
            archive_type=exc.archive_type or archive_type,
            used_patool=patoolib is not None and not zipfile.is_zipfile(archive_path) and not tarfile.is_tarfile(archive_path),
            requires_password=exc.requires_password,
            password_strategy=exc.password_strategy,
            attempted_passwords=list(exc.attempted_passwords),
            password_attempt_count=len(exc.attempted_passwords),
            strategy_supported=exc.strategy_supported,
            outcome_code=exc.outcome_code or ("password_required" if exc.requires_password else "extraction_failed"),
            error=str(exc),
        )
    except (OSError, zipfile.BadZipFile, tarfile.TarError, ValueError) as exc:
        return _build_generic_failure_result(
            archive_path=archive_path,
            archive_type=archive_type,
            normalized_candidates=normalized_candidates,
            error=str(exc),
        )
    except Exception as exc:  # pragma: no cover - depends on external unpackers
        return _build_generic_failure_result(
            archive_path=archive_path,
            archive_type=archive_type,
            normalized_candidates=normalized_candidates,
            error=str(exc),
        )


def read_text_preview(path: Path, max_bytes: int = MAX_TEXT_PREVIEW_BYTES) -> str:
    raw = path.read_bytes()[:max_bytes]
    return raw.decode("utf-8", errors="replace")


def _extract_zip(
    archive_path: Path,
    destination: Path,
    *,
    max_files: int,
    password_candidates: list[str],
) -> tuple[list[Path], str, list[str]]:
    extracted_files: list[Path] = []
    with zipfile.ZipFile(archive_path) as archive:
        names = [info for info in archive.infolist() if not info.is_dir()]
        if len(names) > max_files:
            raise ValueError(f"archive contains too many files: {len(names)} > {max_files}")
        password, attempted_passwords = _resolve_zip_password(archive, names, password_candidates)
        for info in names:
            target_path = _safe_join(destination, info.filename)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            password_bytes = password.encode("utf-8") if password else None
            with archive.open(info, pwd=password_bytes) as source, target_path.open("wb") as handle:
                shutil.copyfileobj(source, handle)
            extracted_files.append(target_path)
    return extracted_files, password, attempted_passwords


def _extract_tar(archive_path: Path, destination: Path, *, max_files: int) -> list[Path]:
    extracted_files: list[Path] = []
    with tarfile.open(archive_path) as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        if len(members) > max_files:
            raise ValueError(f"archive contains too many files: {len(members)} > {max_files}")
        for member in members:
            target_path = _safe_join(destination, member.name)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                continue
            with source, target_path.open("wb") as handle:
                shutil.copyfileobj(source, handle)
            extracted_files.append(target_path)
    return extracted_files


def _extract_with_patool(
    archive_path: Path,
    destination: Path,
    *,
    max_files: int,
    password_candidates: list[str],
) -> tuple[list[Path], str, list[str], str]:
    assert patoolib is not None
    archive_type = _describe_archive_type(archive_path)
    try:
        extracted_files = _extract_with_patool_once(archive_path, destination, max_files=max_files, password="")
        return extracted_files, "", [], ""
    except Exception as exc:
        if not _looks_password_protected_error(str(exc)):
            raise

    if archive_path.suffix.lower() not in PATool_PASSWORD_SUPPORTED_SUFFIXES:
        raise ArchiveHandlingError(
            "archive requires password for extraction; controlled password attempts are not supported for this archive type",
            requires_password=True,
            password_strategy="controlled_non_zip_password_candidates",
            archive_type=archive_type,
            strategy_supported=False,
            outcome_code="password_strategy_unsupported",
        )
    if not password_candidates:
        raise ArchiveHandlingError(
            "archive requires password for extraction; no controlled password candidates are available",
            requires_password=True,
            password_strategy="controlled_non_zip_password_candidates",
            archive_type=archive_type,
            strategy_supported=True,
            outcome_code="password_candidates_unavailable",
        )

    attempted_passwords: list[str] = []
    last_error = "archive requires password for extraction"
    for candidate in password_candidates:
        attempted_passwords.append(candidate)
        _reset_directory(destination)
        try:
            extracted_files = _extract_with_patool_once(
                archive_path,
                destination,
                max_files=max_files,
                password=candidate,
            )
            return (
                extracted_files,
                candidate,
                attempted_passwords,
                "controlled_non_zip_password_candidates",
            )
        except Exception as exc:
            last_error = str(exc)
            if _looks_password_protected_error(last_error):
                continue
            raise

    raise ArchiveHandlingError(
        f"archive requires password for extraction after {len(attempted_passwords)} controlled candidate attempts: {last_error}",
        requires_password=True,
        attempted_passwords=attempted_passwords,
        password_strategy="controlled_non_zip_password_candidates",
        archive_type=archive_type,
        strategy_supported=True,
        outcome_code="password_attempts_exhausted",
    )


def _extract_with_patool_once(archive_path: Path, destination: Path, *, max_files: int, password: str) -> list[Path]:
    assert patoolib is not None
    kwargs = {
        "outdir": str(destination),
        "verbosity": -1,
        "interactive": False,
    }
    program_args = _build_patool_password_args(archive_path, password)
    if program_args:
        kwargs["program_args"] = program_args
    patoolib.extract_archive(str(archive_path), **kwargs)
    extracted_files = [path for path in destination.rglob("*") if path.is_file()]
    if len(extracted_files) > max_files:
        raise ValueError(f"archive contains too many files: {len(extracted_files)} > {max_files}")
    return extracted_files


def _safe_join(base: Path, relative_name: str) -> Path:
    target = (base / relative_name).resolve()
    base_resolved = base.resolve()
    if base_resolved not in target.parents and target != base_resolved:
        raise ValueError(f"unsafe archive path: {relative_name}")
    return target


def _looks_password_protected_error(message: str) -> bool:
    normalized = message.lower()
    return any(
        marker in normalized
        for marker in (
            "password",
            "wrong password",
            "encrypted",
            "passphrase",
            "can not open encrypted archive",
            "密码",
        )
    )


def _resolve_zip_password(archive: zipfile.ZipFile, names: list[object], password_candidates: list[str]) -> tuple[str, list[str]]:
    encrypted = any(getattr(info, "flag_bits", 0) & 0x1 for info in names)
    if not encrypted:
        return "", []

    probe_member = next((info for info in names if not getattr(info, "is_dir", lambda: False)()), None)
    if probe_member is None:
        raise ValueError("archive requires password for extraction")

    attempted_passwords: list[str] = []
    normalized_candidates = _normalize_password_candidates(password_candidates)
    for candidate in normalized_candidates:
        attempted_passwords.append(candidate)
        password_bytes = candidate.encode("utf-8") if candidate else None
        try:
            with archive.open(probe_member, pwd=password_bytes) as source:
                source.read(1)
            return candidate, attempted_passwords
        except RuntimeError as exc:
            if _looks_password_protected_error(str(exc)):
                continue
            raise
        except (zipfile.BadZipFile, OSError):
            continue

    raise ArchiveHandlingError(
        "archive requires password for extraction",
        requires_password=True,
        attempted_passwords=attempted_passwords,
        password_strategy="controlled_weak_password_candidates",
        archive_type="zip",
        strategy_supported=True,
        outcome_code="password_required",
    )


def _normalize_password_candidates(password_candidates: list[str] | tuple[str, ...] | None) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for candidate in list(WEAK_PASSWORD_CANDIDATES) + list(password_candidates or []):
        item = candidate.strip() if candidate is not None else ""
        if item in seen:
            continue
        seen.add(item)
        normalized.append(item)
    return normalized


def _describe_archive_type(archive_path: Path) -> str:
    lowered = archive_path.name.lower()
    for suffix in (".tar.gz", ".tgz", ".tar", ".zip", ".7z", ".rar"):
        if lowered.endswith(suffix):
            return suffix.lstrip(".")
    return archive_path.suffix.lower().lstrip(".") or "archive"


def _build_generic_failure_result(
    *,
    archive_path: Path,
    archive_type: str,
    normalized_candidates: list[str],
    error: str,
) -> ExtractionResult:
    requires_password = _looks_password_protected_error(error)
    return ExtractionResult(
        extracted=False,
        extracted_files=[],
        archive_type=archive_type,
        used_patool=patoolib is not None and archive_type not in {"zip", "tar", "tar.gz", "tgz"},
        requires_password=requires_password,
        password_strategy=(
            "controlled_non_zip_password_candidates"
            if requires_password and archive_type not in {"zip", "tar", "tar.gz", "tgz"}
            else "controlled_weak_password_candidates" if requires_password and archive_type == "zip" else ""
        ),
        attempted_passwords=normalized_candidates if requires_password else [],
        password_attempt_count=len(normalized_candidates) if requires_password else 0,
        strategy_supported=archive_path.suffix.lower() in PATool_PASSWORD_SUPPORTED_SUFFIXES or archive_type == "zip",
        outcome_code="password_required" if requires_password else "extraction_failed",
        error=error,
    )


def _build_patool_password_args(archive_path: Path, password: str) -> list[str]:
    if not password:
        return []
    if archive_path.suffix.lower() in PATool_PASSWORD_SUPPORTED_SUFFIXES:
        return [f"-p{password}"]
    return []


def _reset_directory(path: Path) -> None:
    cleanup_path(path)
    path.mkdir(parents=True, exist_ok=True)
