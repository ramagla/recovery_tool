import os
from typing import Dict, Any, List

from .device_reader import normalize_volume_path, require_windows_admin, RawVolumeReader
from .fs_fat32 import detect_fat32, recover_deleted_fat32
from .fs_exfat import detect_exfat, recover_deleted_exfat
from .fs_ntfs import detect_ntfs, recover_deleted_ntfs

def recover_deleted_from_volume(
    drive_path: str,
    output_dir: str,
    selected_exts: List[str],
    progress_cb=None,
) -> List[Dict[str, Any]]:
    """
    Undelete estilo Recuva:
    - abre o volume raw (\\\\.\\X:) e tenta recuperar entradas deletadas.
    """
    require_windows_admin()
    vol = normalize_volume_path(drive_path)

    os.makedirs(output_dir, exist_ok=True)

    with RawVolumeReader(vol.raw_path) as r:
        if detect_exfat(r):
            if progress_cb:
                progress_cb(processed_bytes=0, total_bytes=1, message="Detectado exFAT. Iniciando undelete...")
            return recover_deleted_exfat(r, output_dir, selected_exts, progress_cb=progress_cb)

        if detect_ntfs(r):
            if progress_cb:
                progress_cb(processed_bytes=0, total_bytes=1, message="Detectado NTFS. Iniciando undelete...")
            return recover_deleted_ntfs(r, output_dir, selected_exts, progress_cb=progress_cb)

        if detect_fat32(r):
            if progress_cb:
                progress_cb(processed_bytes=0, total_bytes=1, message="Detectado FAT32. Iniciando undelete...")
            return recover_deleted_fat32(r, output_dir, selected_exts, progress_cb=progress_cb)

        raise RuntimeError("Sistema de arquivos não reconhecido (FAT32/exFAT/NTFS).")