from __future__ import annotations

import shutil


def inspect_archive_tools(patool_binary: str, unrar_binary: str) -> tuple[bool, str]:
    patool_found = shutil.which(patool_binary)
    unrar_found = shutil.which(unrar_binary)
    if not patool_found:
        return False, f"patool binary not found: {patool_binary}"
    if not unrar_found:
        return False, f"unrar binary not found: {unrar_binary}"
    return True, f"archive tools ready: patool={patool_found}, unrar={unrar_found}"
