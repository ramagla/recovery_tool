import math
import os
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

from .device_reader import RawVolumeReader

# exFAT directory entry types
ENTRY_FILE = 0x85          # in-use file directory entry
ENTRY_STREAM = 0xC0        # stream extension
ENTRY_NAME = 0xC1          # filename entry
IN_USE_MASK = 0x80         # bit 7 indicates entry in-use

@dataclass(frozen=True)
class ExFATVBR:
    bytes_per_sector: int
    sectors_per_cluster: int
    fat_offset_sectors: int
    fat_length_sectors: int
    cluster_heap_offset_sectors: int
    cluster_count: int
    root_dir_first_cluster: int
    volume_length_sectors: int

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

def detect_exfat(reader: RawVolumeReader) -> bool:
    bs = reader.read_at(0, 512)
    return bs[3:11] == b"EXFAT   "

def _u16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off+2], "little")

def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off+4], "little")

def _u64(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off+8], "little")

def parse_vbr(reader: RawVolumeReader) -> ExFATVBR:
    bs = reader.read_at(0, 512)

    vol_len = _u64(bs, 72)
    fat_off = _u32(bs, 80)
    fat_len = _u32(bs, 84)
    heap_off = _u32(bs, 88)
    cluster_cnt = _u32(bs, 92)
    root_cl = _u32(bs, 96)

    bps_shift = bs[108]
    spc_shift = bs[109]
    bps = 1 << bps_shift
    spc = 1 << spc_shift

    if bps < 512 or spc < 1:
        raise ValueError("VBR exFAT inválido (bps/spc)")

    return ExFATVBR(
        bytes_per_sector=bps,
        sectors_per_cluster=spc,
        fat_offset_sectors=fat_off,
        fat_length_sectors=fat_len,
        cluster_heap_offset_sectors=heap_off,
        cluster_count=cluster_cnt,
        root_dir_first_cluster=root_cl,
        volume_length_sectors=vol_len,
    )

def cluster_to_offset(vbr: ExFATVBR, cluster: int) -> int:
    if cluster < 2:
        cluster = 2
    heap_base = vbr.cluster_heap_offset_sectors * vbr.bytes_per_sector
    return heap_base + (cluster - 2) * vbr.cluster_size

def fat_entry_offset(vbr: ExFATVBR, cluster: int) -> int:
    fat_base = vbr.fat_offset_sectors * vbr.bytes_per_sector
    return fat_base + cluster * 4

def read_fat_entry(reader: RawVolumeReader, vbr: ExFATVBR, cluster: int) -> int:
    off = fat_entry_offset(vbr, cluster)
    raw = reader.read_at(off, 4)
    return int.from_bytes(raw, "little")

def follow_chain(reader: RawVolumeReader, vbr: ExFATVBR, start_cluster: int, max_steps: int = 2_000_000) -> List[int]:
    chain: List[int] = []
    c = start_cluster
    steps = 0
    while c >= 2 and steps < max_steps:
        chain.append(c)
        nxt = read_fat_entry(reader, vbr, c)
        # exFAT EOC: >= 0xFFFFFFF8
        if nxt == 0 or nxt >= 0xFFFFFFF8:
            break
        c = nxt
        steps += 1
    return chain

def _entry_type(ent: bytes) -> int:
    return ent[0]

def _is_in_use(entry_type: int) -> bool:
    return (entry_type & IN_USE_MASK) != 0

def _base_type(entry_type: int) -> int:
    return entry_type & 0x7F

def _decode_name_chars(ent: bytes) -> str:
    # name entry stores 15 UTF-16LE chars starting at offset 2, length 30 bytes
    raw = ent[2:32]
    try:
        s = raw.decode("utf-16le", errors="ignore")
    except Exception:
        s = ""
    return s.rstrip("\x00")

@dataclass(frozen=True)
class ExFATFileMeta:
    name: str
    first_cluster: int
    data_length: int
    no_fat_chain: bool

def _parse_file_set(entries: List[bytes]) -> Optional[ExFATFileMeta]:
    # Expected: file entry + stream ext + 1..n filename entries
    if len(entries) < 3:
        return None

    file_ent = entries[0]
    stream_ent = entries[1]

    if _base_type(_entry_type(file_ent)) != (_base_type(ENTRY_FILE)):
        return None
    if _base_type(_entry_type(stream_ent)) != (_base_type(ENTRY_STREAM)):
        return None

    # stream extension fields
    # offset 3: general secondary flags (bit 0: AllocationPossible? not used here)
    # offset 1: SecondaryCount
    # offset 2: SetChecksum
    # offset 3: GeneralSecondaryFlags
    # offset 20..27: DataLength (uint64)
    # offset 28..31: FirstCluster (uint32)
    # offset 4: NameLength (uint8)
    name_len = stream_ent[4]
    gen_flags = stream_ent[3]
    no_fat_chain = (gen_flags & 0x02) != 0  # NoFatChain flag (common)

    data_len = int.from_bytes(stream_ent[20:28], "little")
    first_cluster = int.from_bytes(stream_ent[28:32], "little")

    # filename entries
    parts: List[str] = []
    for ent in entries[2:]:
        if _base_type(_entry_type(ent)) != (_base_type(ENTRY_NAME)):
            continue
        parts.append(_decode_name_chars(ent))

    name = "".join(parts)
    if name_len and len(name) > name_len:
        name = name[:name_len]

    name = name.strip()
    if not name:
        return None

    return ExFATFileMeta(
        name=name,
        first_cluster=first_cluster,
        data_length=data_len,
        no_fat_chain=no_fat_chain,
    )

def _scan_directory_file_sets(
    reader: RawVolumeReader,
    vbr: ExFATVBR,
    dir_first_cluster: int,
) -> List[Tuple[bool, ExFATFileMeta]]:
    """
    Retorna lista de (is_deleted, meta) para file-sets encontrados no diretório.
    Em exFAT, o bit IN_USE (0x80) do entry type indica se a entrada está ativa.
    Se não estiver em uso, em geral é candidato a deletado.
    """
    file_sets: List[Tuple[bool, ExFATFileMeta]] = []

    # Diretório em exFAT é um arquivo (sequência de clusters). Frequentemente no_fat_chain (contíguo),
    # mas aqui tentamos via FAT para caminhar. Se FAT estiver “limpa”, tentamos alguns clusters contíguos.
    chain = follow_chain(reader, vbr, dir_first_cluster)
    if len(chain) <= 1:
        # fallback contíguo (diretório raiz normalmente pequeno)
        chain = [dir_first_cluster + i for i in range(64)]  # até 64 clusters como fallback

    buf_all = b""
    for cl in chain:
        off = cluster_to_offset(vbr, cl)
        buf_all += reader.read_at(off, vbr.cluster_size)

    # each entry is 32 bytes
    i = 0
    while i + 32 <= len(buf_all):
        ent = buf_all[i:i+32]
        et = _entry_type(ent)
        if et == 0x00:
            break  # end of directory

        base = _base_type(et)

        if base == _base_type(ENTRY_FILE):
            secondary_count = ent[1]
            set_entries = [ent]
            for k in range(secondary_count):
                j = i + 32 * (k + 1)
                if j + 32 > len(buf_all):
                    break
                set_entries.append(buf_all[j:j+32])

            meta = _parse_file_set(set_entries)
            if meta:
                deleted = not _is_in_use(et)
                file_sets.append((deleted, meta))

            i = i + 32 * (secondary_count + 1)
            continue

        i += 32

    return file_sets

def _ext_allowed(name: str, allowed_exts: List[str]) -> bool:
    if not allowed_exts:
        return True
    ext = os.path.splitext(name)[1].lower().lstrip(".")
    allowed = {e.lower().lstrip(".") for e in allowed_exts}
    return ext in allowed

def _safe_output_path(output_dir: str, filename: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    filename = filename.replace("\\", "_").replace("/", "_").strip()
    out = os.path.join(output_dir, filename)
    base, ext = os.path.splitext(out)
    n = 1
    while os.path.exists(out):
        out = f"{base}__{n}{ext}"
        n += 1
    return out

def _recover_exfat_file(
    reader: RawVolumeReader,
    vbr: ExFATVBR,
    meta: ExFATFileMeta,
    output_dir: str,
) -> Optional[Dict[str, Any]]:
    if meta.first_cluster < 2 or meta.data_length <= 0:
        return None

    out_path = _safe_output_path(output_dir, meta.name)

    bytes_needed = meta.data_length
    clusters_needed = int(math.ceil(bytes_needed / vbr.cluster_size))

    if meta.no_fat_chain:
        chain = [meta.first_cluster + i for i in range(clusters_needed)]
        method = "exfat_undelete_contiguous"
    else:
        chain = follow_chain(reader, vbr, meta.first_cluster)
        if len(chain) <= 1:
            chain = [meta.first_cluster + i for i in range(clusters_needed)]
            method = "exfat_undelete_fat_missing_assume_contiguous"
        else:
            method = "exfat_undelete_fat_chain"

    with open(out_path, "wb") as f:
        remaining = bytes_needed
        for cl in chain:
            if remaining <= 0:
                break
            off = cluster_to_offset(vbr, cl)
            chunk = reader.read_at(off, min(vbr.cluster_size, remaining))
            f.write(chunk)
            remaining -= len(chunk)

    return {
        "recovered_path": out_path,
        "method": method,
        "offset": cluster_to_offset(vbr, meta.first_cluster),
        "size_bytes": meta.data_length,
        "ext": os.path.splitext(meta.name)[1].lower().lstrip("."),
        "no_fat_chain": meta.no_fat_chain,
    }

def recover_deleted_exfat(
    reader: RawVolumeReader,
    output_dir: str,
    selected_exts: List[str],
    progress_cb=None,
) -> List[Dict[str, Any]]:
    vbr = parse_vbr(reader)
    total_bytes = vbr.volume_length_sectors * vbr.bytes_per_sector

    if progress_cb:
        progress_cb(processed_bytes=0, total_bytes=total_bytes, message="exFAT: lendo diretório raiz...")

    file_sets = _scan_directory_file_sets(reader, vbr, vbr.root_dir_first_cluster)
    deleted_sets = [(d, m) for (d, m) in file_sets if d]

    if progress_cb:
        progress_cb(
            processed_bytes=min(total_bytes, 16 * 1024 * 1024),
            total_bytes=total_bytes,
            message=f"exFAT: candidatos deletados encontrados: {len(deleted_sets)}"
        )

    results: List[Dict[str, Any]] = []
    processed = 0
    idx = 0
    for (is_deleted, meta) in deleted_sets:
        idx += 1
        if not _ext_allowed(meta.name, selected_exts):
            processed = int((idx / max(1, len(deleted_sets))) * total_bytes)
            if progress_cb:
                progress_cb(processed_bytes=processed, total_bytes=total_bytes, message=f"exFAT: filtrando {idx}/{len(deleted_sets)}")
            continue

        r = _recover_exfat_file(reader, vbr, meta, output_dir)
        if r:
            results.append(r)

        processed = int((idx / max(1, len(deleted_sets))) * total_bytes)
        if progress_cb:
            progress_cb(processed_bytes=processed, total_bytes=total_bytes, message=f"exFAT: recuperando {idx}/{len(deleted_sets)}")

    if progress_cb:
        progress_cb(processed_bytes=total_bytes, total_bytes=total_bytes, message="exFAT: finalizado.")

    return results