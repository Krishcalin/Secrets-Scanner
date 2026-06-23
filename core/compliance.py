"""Compliance mapping — tie each finding to the controls it violates.

A hardcoded secret isn't just a bug; it's a control failure auditors care about.
This module maps each detection rule to the relevant CWE, OWASP Top 10 (2021),
PCI DSS v4.0, and NIST SP 800-53 Rev 5 controls so a scan doubles as evidence for
a GRC review.

Most secrets map to **CWE-798 (Use of Hard-coded Credentials)**; private keys map
to **CWE-321 (Use of Hard-coded Cryptographic Key)** and JWTs to **CWE-522
(Insufficiently Protected Credentials)**.
"""

from __future__ import annotations

from core.models import ScanResult

# (id, title) per framework
CWE_HARDCODED = ("CWE-798", "Use of Hard-coded Credentials")
CWE_CRYPTO_KEY = ("CWE-321", "Use of Hard-coded Cryptographic Key")
CWE_PROTECTED_CRED = ("CWE-522", "Insufficiently Protected Credentials")

OWASP_AUTH = ("A07:2021", "Identification and Authentication Failures")
OWASP_CRYPTO = ("A02:2021", "Cryptographic Failures")

PCI_HARDCODE = ("PCI DSS 8.6.2", "Do not hard-code passwords/credentials in files or scripts")
PCI_SECURE_DEV = ("PCI DSS 6.2.4", "Address common coding vulnerabilities in software development")

NIST_IA5 = ("IA-5", "Authenticator Management")
NIST_SC12 = ("SC-12", "Cryptographic Key Establishment and Management")

# Rules that represent cryptographic key material rather than a plain credential
_KEY_RULES = {"private_key_block", "private_key_assignment", "gcp_service_account"}
_JWT_RULES = {"jwt"}

_FRAMEWORK_ORDER = ["CWE", "OWASP_2021", "PCI_DSS_4", "NIST_800_53"]


def controls_for(rule_id: str) -> dict[str, list[tuple[str, str]]]:
    """Return the controls implicated by a single rule, grouped by framework."""
    if rule_id in _KEY_RULES:
        cwe, owasp, nist = [CWE_CRYPTO_KEY], [OWASP_CRYPTO], [NIST_IA5, NIST_SC12]
    elif rule_id in _JWT_RULES:
        cwe, owasp, nist = [CWE_PROTECTED_CRED], [OWASP_AUTH], [NIST_IA5]
    else:
        cwe, owasp, nist = [CWE_HARDCODED], [OWASP_AUTH], [NIST_IA5]
    return {
        "CWE": cwe,
        "OWASP_2021": owasp,
        "PCI_DSS_4": [PCI_HARDCODE, PCI_SECURE_DEV],
        "NIST_800_53": nist,
    }


def summarize(result: ScanResult) -> dict:
    """Aggregate the controls implicated across a whole scan.

    Returns ``{"frameworks": {framework: {control_id: {title, count}}}, ...}``.
    """
    frameworks: dict[str, dict[str, dict]] = {f: {} for f in _FRAMEWORK_ORDER}
    for finding in result.findings:
        for framework, controls in controls_for(finding.rule_id).items():
            bucket = frameworks[framework]
            for cid, title in controls:
                entry = bucket.setdefault(cid, {"title": title, "count": 0})
                entry["count"] += 1
    implicated = sum(len(b) for b in frameworks.values())
    return {
        "frameworks": frameworks,
        "controls_implicated": implicated,
        "findings_mapped": result.count,
    }
