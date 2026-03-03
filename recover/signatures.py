# PARA (com DWG + 7Z)
from dataclasses import dataclass
from typing import Optional, Callable

@dataclass(frozen=True)
class Signature:
    ext: str
    magic: bytes
    end_marker: Optional[bytes] = None
    max_size_bytes: int = 50 * 1024 * 1024
    validator: Optional[Callable[[bytes], bool]] = None


def is_zip_like(buf: bytes) -> bool:
    return buf.startswith(b"PK\x03\x04") or buf.startswith(b"PK\x05\x06") or buf.startswith(b"PK\x07\x08")


def is_7z_like(buf: bytes) -> bool:
    return buf.startswith(b"7z\xBC\xAF\x27\x1C")


SIGNATURES = [
    Signature(ext="pdf", magic=b"%PDF-", end_marker=b"%%EOF", max_size_bytes=200 * 1024 * 1024),
    Signature(ext="jpg", magic=b"\xFF\xD8\xFF", end_marker=b"\xFF\xD9", max_size_bytes=80 * 1024 * 1024),
    Signature(ext="png", magic=b"\x89PNG\r\n\x1a\n", end_marker=b"IEND", max_size_bytes=80 * 1024 * 1024),

    Signature(ext="zip", magic=b"PK\x03\x04", end_marker=None, max_size_bytes=300 * 1024 * 1024, validator=is_zip_like),

    # 7z
    Signature(ext="7z", magic=b"7z\xBC\xAF\x27\x1C", end_marker=None, max_size_bytes=600 * 1024 * 1024, validator=is_7z_like),

    # DWG (Autodesk) — começa com "AC10" (AC1015/AC1027 etc.)
    Signature(ext="dwg", magic=b"AC10", end_marker=None, max_size_bytes=400 * 1024 * 1024),
]