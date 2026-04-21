"""
PII Encryption at Rest
=======================
Uses Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256) from the
cryptography package to protect personally identifiable information stored
in the database.

Key management:
  - Set  PHISHSIM_ENCRYPTION_KEY  environment variable to a Fernet key.
  - Generate a key:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  - If the env var is NOT set, encryption is DISABLED and data is stored plain.
    This maintains backward compatibility for existing deployments.
  - NEVER commit the key to version control. Store it securely (env var, secrets manager).

Fields encrypted:
  Target.email, Target.name, Target.department (employee PII)
  EmployeeRiskScore.email, .name, .department
  RiskSignal.email

Encrypted values are stored with an "enc:" prefix so the system can distinguish
encrypted from unencrypted (plain-text) values — supporting mixed migrations.
"""

import os
import logging
from typing import Optional

log = logging.getLogger(__name__)

_fernet = None
_ENCRYPTION_AVAILABLE = False
_PREFIX = "enc:"


def _get_fernet():
    global _fernet, _ENCRYPTION_AVAILABLE
    if _fernet is not None:
        return _fernet

    key = os.getenv("PHISHSIM_ENCRYPTION_KEY", "").strip()
    if not key:
        return None

    try:
        from cryptography.fernet import Fernet
        _fernet = Fernet(key.encode() if isinstance(key, str) else key)
        _ENCRYPTION_AVAILABLE = True
        log.info("PII encryption enabled (Fernet).")
        return _fernet
    except Exception as e:
        log.error(f"Failed to initialise Fernet encryption: {e}. PII will be stored unencrypted.")
        return None


def encrypt(value: Optional[str]) -> Optional[str]:
    """
    Encrypt a string value.
    Returns the encrypted value prefixed with 'enc:', or the original value
    if encryption is not configured.
    """
    if value is None:
        return value
    f = _get_fernet()
    if f is None:
        return value   # Encryption not configured — store plain
    if value.startswith(_PREFIX):
        return value   # Already encrypted
    try:
        return _PREFIX + f.encrypt(value.encode()).decode()
    except Exception as e:
        log.error(f"Encryption error: {e}")
        return value


def decrypt(value: Optional[str]) -> Optional[str]:
    """
    Decrypt a value that was encrypted with encrypt().
    Returns the original plain-text, or the value as-is if it was not encrypted.
    """
    if value is None:
        return value
    if not value.startswith(_PREFIX):
        return value   # Not encrypted — return as-is (handles plain-text legacy data)
    f = _get_fernet()
    if f is None:
        log.warning("Cannot decrypt: PHISHSIM_ENCRYPTION_KEY not set.")
        return value
    try:
        return f.decrypt(value[len(_PREFIX):].encode()).decode()
    except Exception as e:
        log.error(f"Decryption error: {e}")
        return value


def is_enabled() -> bool:
    """Returns True if encryption is configured and active."""
    return _get_fernet() is not None


def rotate_key(old_key: str, new_key: str, db) -> dict:
    """
    Re-encrypt all PII fields with a new key.
    Used when rotating the encryption key.
    Returns a summary of records updated.
    """
    try:
        from cryptography.fernet import Fernet
        old_f = Fernet(old_key.encode())
        new_f = Fernet(new_key.encode())
    except Exception as e:
        return {"error": str(e)}

    import models
    updated = 0

    def _reencrypt(val):
        if not val or not val.startswith(_PREFIX):
            return val
        try:
            plain = old_f.decrypt(val[len(_PREFIX):].encode()).decode()
            return _PREFIX + new_f.encrypt(plain.encode()).decode()
        except Exception:
            return val

    # Rotate Target PII
    for t in db.query(models.Target).all():
        t.email      = _reencrypt(t.email)
        t.name       = _reencrypt(t.name)
        t.department = _reencrypt(t.department)
        updated += 1

    # Rotate EmployeeRiskScore PII
    for e in db.query(models.EmployeeRiskScore).all():
        e.email      = _reencrypt(e.email)
        e.name       = _reencrypt(e.name)
        e.department = _reencrypt(e.department)
        updated += 1

    db.commit()
    return {"rotated": updated}
