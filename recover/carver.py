import os
from typing import List, Dict, Any
from .signatures import SIGNATURES, Signature
from .hasher import sha256_file
from .audit import ensure_dir, now_iso

CHUNK_SIZE = 4 * 1024 * 1024  # 4MB
OVERLAP = 64 * 1024           # 64KB (para não perder assinatura na borda)

def _find_all(data: bytes, needle: bytes) -> List[int]:
    positions = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    return positions

def _next_signature_offset(global_offsets: List[int], current_offset: int) -> int:
    # Retorna o próximo offset maior que current_offset; senão -1
    for off in global_offsets:
        if off > current_offset:
            return off
    return -1

def carve_file(
    source_path: str,
    output_dir: str,
    selected_exts: List[str],
    progress_cb=None,
) -> List[Dict[str, Any]]:
    """
    MVP de carving:
    - Varre o arquivo (imagem/backup) buscando magic bytes.
    - Extrai até achar end_marker, OU até max_size, OU até a próxima assinatura.
    """
    ensure_dir(output_dir)
    results: List[Dict[str, Any]] = []

    total_size = os.path.getsize(source_path)

    # Pré-mapeia assinaturas selecionadas
    sigs = [s for s in SIGNATURES if s.ext in selected_exts]

    # Vamos coletar offsets “candidatos” num passe (streaming) para saber próximos limites.
    # MVP: coletamos só offsets das magics principais (não de end_marker).
    candidates: List[int] = []

    with open(source_path, "rb") as f:
        pos = 0
        tail = b""
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            data = tail + chunk
            base_pos = pos - len(tail)

            for sig in sigs:
                for rel in _find_all(data, sig.magic):
                    candidates.append(base_pos + rel)

            # atualiza progresso
            pos += len(chunk)
            if progress_cb:
                progress_cb(processed_bytes=pos, total_bytes=total_size)

            tail = data[-OVERLAP:] if len(data) > OVERLAP else data

    candidates = sorted(set([c for c in candidates if 0 <= c < total_size]))

    # Agora extrai cada candidato
    with open(source_path, "rb") as f:
        for idx, start_off in enumerate(candidates, start=1):
            # Identifica qual assinatura bate nesse offset
            f.seek(start_off)
            header = f.read(16)
            matched: Signature | None = None
            for sig in sigs:
                if header.startswith(sig.magic):
                    matched = sig
                    break
            if not matched:
                continue

            # Determina limite “hard” do recorte
            next_off = _next_signature_offset(candidates, start_off)
            hard_limit = total_size if next_off == -1 else next_off
            hard_limit = min(hard_limit, start_off + matched.max_size_bytes)

            f.seek(start_off)
            blob = f.read(hard_limit - start_off)

            # Se tem end_marker, tenta cortar até ele
            if matched.end_marker:
                end_idx = blob.find(matched.end_marker)
                if end_idx != -1:
                    # inclui o marcador no recorte
                    blob = blob[: end_idx + len(matched.end_marker)]

            # Validação simples (quando aplicável)
            if matched.validator and not matched.validator(blob[:8]):
                continue

            out_name = f"recovered_{idx:06d}_{start_off}.{matched.ext}"
            out_path = os.path.join(output_dir, out_name)

            with open(out_path, "wb") as out:
                out.write(blob)

            file_hash = sha256_file(out_path)

            results.append({
                "recovered_path": out_path,
                "method": "carving",
                "offset": start_off,
                "size_bytes": os.path.getsize(out_path),
                "sha256": file_hash,
                "ext": matched.ext,
                "timestamp": now_iso(),
            })

            if progress_cb:
                progress_cb(found_files=len(results))

    return results