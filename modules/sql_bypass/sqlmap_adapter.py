from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from .models import SQLBypassCandidate, TamperRecommendation, WAFProfile


FORBIDDEN_SQLMAP_OPTIONS = {"--dump", "--dbs", "--tables", "--os-shell", "--file-read", "--file-write", "--sql-shell"}


def build_safe_sqlmap_command(
    candidate: SQLBypassCandidate,
    waf_profile: WAFProfile,
    tamper_recommendations: list[TamperRecommendation],
) -> dict[str, object]:
    base_command = [
        "sqlmap",
        "-u",
        _target_url(candidate),
        "--batch",
        "--risk=1",
        "--level=1",
        "--technique=BEU",
        "--timeout=5",
        "--retries=0",
        "-p",
        candidate.parameter,
    ]
    if candidate.method == "POST" and candidate.baseline_body:
        base_command.extend(["--data", _redacted_data(candidate)])

    recommendation_names = [item for item in _recommendation_names(tamper_recommendations)]
    primary = _with_tamper_chain(base_command, recommendation_names[:3])
    variants: list[list[str]] = []
    if len(recommendation_names) > 1:
        variants.append(_with_tamper_chain(base_command, recommendation_names[1:4]))
    if len(recommendation_names) > 3:
        variants.append(_with_tamper_chain(base_command, recommendation_names[:2]))

    primary = [part for part in primary if part not in FORBIDDEN_SQLMAP_OPTIONS]
    variant_commands = [[part for part in item if part not in FORBIDDEN_SQLMAP_OPTIONS] for item in variants[:3]]
    return {
        "execution_mode": "generated_only",
        "waf_type": waf_profile.waf_type,
        "primary_command": primary,
        "variant_commands": variant_commands,
        "primary_display": _display_command(primary),
        "variant_displays": [_display_command(item) for item in variant_commands],
        "blocked_options": sorted(FORBIDDEN_SQLMAP_OPTIONS),
    }


def _with_tamper_chain(command: list[str], tampers: list[str]) -> list[str]:
    built = list(command)
    chain = [item for item in tampers if item][:3]
    if chain:
        built.append(f"--tamper={','.join(chain)}")
    return built


def _target_url(candidate: SQLBypassCandidate) -> str:
    parsed = urlparse(candidate.baseline_url or candidate.page_url)
    if not parsed.scheme or not parsed.netloc:
        return candidate.baseline_url or candidate.page_url
    return urlunparse(parsed._replace(query=f"{candidate.parameter}=1", fragment=""))


def _redacted_data(candidate: SQLBypassCandidate) -> str:
    return f"{candidate.parameter}=1"


def _display_command(command: list[str]) -> str:
    return " ".join(f'"{part}"' if " " in part else part for part in command)


def _recommendation_names(recommendations: list[object]) -> list[str]:
    normalized: list[tuple[int, str]] = []
    for item in recommendations:
        if isinstance(item, TamperRecommendation):
            if item.name:
                normalized.append((item.rank, item.name))
            continue
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            if name:
                try:
                    rank = int(item.get("rank", 999))
                except (TypeError, ValueError):
                    rank = 999
                normalized.append((rank, name))
    return [name for _rank, name in sorted(normalized, key=lambda entry: (entry[0], entry[1]))]
