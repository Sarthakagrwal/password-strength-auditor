"""pwaudit — password strength auditor with private breach checking.

Combines a transparent charset-entropy model, pattern detectors, the ``zxcvbn``
realistic estimator, and a privacy-preserving Have I Been Pwned breach lookup
(k-anonymity: only the first 5 hex characters of the password's SHA-1 hash ever
leave the machine).
"""

from pwaudit.audit import AuditReport, audit

__all__ = ["AuditReport", "audit"]
__version__ = "0.1.0"
