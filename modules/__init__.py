from .backup_audit_extended import run as run_backup_audit_extended
from .config_audit import run as run_config_audit
from .cors_audit import run as run_cors_audit
from .js_audit import run as run_js_audit
from .jwt_audit import run as run_jwt_audit
from .permission_bypass import run as run_permission_bypass
from .poc_verify import run as run_poc_verify
from .recon import run as run_recon
from .state_bootstrap import run as run_state_bootstrap
from .ssrf_triage import run as run_ssrf_triage
from .sql_bypass import run as run_sql_bypass
from .sql_scan import run as run_sql_scan
from .weak_password import run as run_weak_password
from .xss_triage import run as run_xss_triage

SKILL_NATIVE_MODULE_RUNNERS = {
    "state_bootstrap": run_state_bootstrap,
    "recon": run_recon,
    "backup_audit_extended": run_backup_audit_extended,
    "config_audit": run_config_audit,
    "permission_bypass": run_permission_bypass,
    "sql_scan": run_sql_scan,
    "sql_bypass": run_sql_bypass,
    "js_audit": run_js_audit,
    "xss_triage": run_xss_triage,
    "ssrf_triage": run_ssrf_triage,
    "poc_verify": run_poc_verify,
    "weak_password": run_weak_password,
    "cors_audit": run_cors_audit,
    "jwt_audit": run_jwt_audit,
}

__all__ = [
    "run_recon",
    "run_state_bootstrap",
    "run_backup_audit_extended",
    "run_config_audit",
    "run_permission_bypass",
    "run_sql_scan",
    "run_sql_bypass",
    "run_js_audit",
    "run_xss_triage",
    "run_ssrf_triage",
    "run_poc_verify",
    "run_weak_password",
    "run_cors_audit",
    "run_jwt_audit",
    "SKILL_NATIVE_MODULE_RUNNERS",
]
