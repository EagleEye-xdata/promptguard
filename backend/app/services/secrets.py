"""Protect target credentials at rest and reveal them only for outbound calls."""
import base64
import hashlib
from cryptography.fernet import Fernet

PREFIX="enc:"

def _fernet(secret:str)->Fernet:
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))

def protect(value:str|None,secret:str)->str|None:
    if not value or value.startswith(PREFIX) or not secret:return value
    return PREFIX+_fernet(secret).encrypt(value.encode()).decode()

def reveal(value:str|None,secret:str)->str|None:
    if not value or not value.startswith(PREFIX):return value
    if not secret:raise RuntimeError("encrypted target credential requires EAGLEI_ENCRYPTION_KEY")
    return _fernet(secret).decrypt(value[len(PREFIX):].encode()).decode()

def mask(value:str|None)->str|None:
    if not value:return value
    if value.startswith(PREFIX):return "****(encrypted)"
    scheme,separator,token=value.partition(" ");tail=token[-4:] if separator and len(token)>8 else value[-4:] if len(value)>8 else ""
    return f"{scheme} ****{tail}" if separator else f"****{tail}"
