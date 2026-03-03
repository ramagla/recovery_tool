import os
import shutil
from typing import List, Dict, Any

from .audit import ensure_dir, now_iso
from .hasher import sha256_file


def _norm_exts(exts: List[str]) -> List[str]:
    out = []
    for e in exts:
        e = e.strip().lower().lstrip(".")
        if e:
            out.append(e)
    return sorted(set(out))


def recover_from_folder(
    source_dir: str,
    output_dir: str,
    selected_exts: List[str],
    progress_cb=None,
) -> List[Dict[str, Any]]:

    selected = _norm_exts(selected_exts)

    if not os.path.isdir(source_dir):
        raise ValueError(f"Origem inválida (não é pasta): {source_dir}")

    ensure_dir(output_dir)

    results: List[Dict[str, Any]] = []
    total_files = 0
    copied_files = 0
    scanned_files = 0

    # 1) conta total (com atualização periódica)
    for root, _, files in os.walk(source_dir):
        for name in files:
            scanned_files += 1
            ext = os.path.splitext(name)[1].lower().lstrip(".")
            if ext in selected:
                total_files += 1

            if progress_cb and (scanned_files % 1500 == 0):
                progress_cb(stage="counting", scanned_files=scanned_files, total_files=total_files, found_files=0)

    if progress_cb:
        progress_cb(stage="counting_done", scanned_files=scanned_files, total_files=total_files, found_files=0)

    # 2) copia (com progresso real)
    for root, _, files in os.walk(source_dir):
        for name in files:
            ext = os.path.splitext(name)[1].lower().lstrip(".")
            if ext not in selected:
                continue

            src_path = os.path.join(root, name)
            rel_path = os.path.relpath(src_path, source_dir)
            dest_path = os.path.join(output_dir, rel_path)

            ensure_dir(os.path.dirname(dest_path))
            shutil.copy2(src_path, dest_path)

            file_hash = sha256_file(dest_path)
            size_bytes = os.path.getsize(dest_path)

            results.append({
                "recovered_path": dest_path,
                "method": "folder_copy",
                "offset": None,
                "size_bytes": size_bytes,
                "sha256": file_hash,
                "ext": ext,
                "timestamp": now_iso(),
                "source_path": src_path,
            })

            copied_files += 1
            if progress_cb:
                progress_cb(stage="copying", found_files=copied_files, total_files=total_files)

    return results