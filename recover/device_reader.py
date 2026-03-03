import os
import sys
from dataclasses import dataclass
from typing import BinaryIO, Optional

@dataclass(frozen=True)
class VolumeInfo:
    raw_path: str           # exemplo: \\.\E:
    logical_path: str       # exemplo: E:\
    is_windows: bool

def is_windows() -> bool:
    return os.name == "nt"

def normalize_volume_path(user_drive_path: str) -> VolumeInfo:
    """
    Recebe algo como:
    - "E:\\" (do select)
    - "E:"   (eventual)
    e retorna:
    - raw_path: "\\\\.\\E:"
    - logical_path: "E:\\"
    """
    p = (user_drive_path or "").strip()

    if not p:
        raise ValueError("drive_path vazio")

    if len(p) >= 2 and p[1] == ":":
        letter = p[0].upper()
        logical = f"{letter}:\\"
        raw = f"\\\\.\\{letter}:"
        return VolumeInfo(raw_path=raw, logical_path=logical, is_windows=is_windows())

    raise ValueError(f"Formato de drive_path inválido: {user_drive_path}")

def require_windows_admin() -> None:
    if not is_windows():
        raise RuntimeError("Undelete raw foi implementado inicialmente para Windows.")

    try:
        import ctypes  # pylint: disable=import-error
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError("Execute como Administrador para ler o volume (\\\\.\\X:).")
    except Exception as e:
        if isinstance(e, PermissionError):
            raise
        raise PermissionError("Não foi possível validar privilégio de Administrador.") from e

class RawVolumeReader:
    def __init__(self, raw_volume_path: str):
        self.raw_volume_path = raw_volume_path
        self._f: Optional[BinaryIO] = None

    def __enter__(self) -> "RawVolumeReader":
        self._f = open(self.raw_volume_path, "rb", buffering=0)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._f:
            self._f.close()
            self._f = None

    def read_at(self, offset: int, size: int) -> bytes:
        if not self._f:
            raise RuntimeError("Reader não aberto")
        self._f.seek(offset)
        return self._f.read(size)

    def size_bytes(self) -> int:
        if not self._f:
            raise RuntimeError("Reader não aberto")
        cur = self._f.tell()
        self._f.seek(0, os.SEEK_END)
        end = self._f.tell()
        self._f.seek(cur, os.SEEK_SET)
        return end