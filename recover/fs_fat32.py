import math
import os
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

from .device_reader import RawVolumeReader

EOC_MIN = 0x0FFFFFF8  # FAT32 end-of-chain mínimo

@dataclass(frozen=True)
class FAT32BPB:
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    sectors_per_fat: int
    root_cluster: int
    total_sectors: int

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

def _u16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off+2], "little")

def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off+4], "little")

def parse_bpb(boot_sector: bytes) -> FAT32BPB:
    bps = _u16(boot_sector, 11)
    spc = boot_sector[13]
    rsv = _u16(boot_sector, 14)
    nf = boot_sector[16]
    tot16 = _u16(boot_sector, 19)
    tot32 = _u32(boot_sector, 32)
    total = tot32 if tot16 == 0 else tot16

    spf16 = _u16(boot_sector, 22)
    spf32 = _u32(boot_sector, 36)
    spf = spf32 if spf16 == 0 else spf16

    root_cluster = _u32(boot_sector, 44)

    if bps == 0 or spc == 0 or nf == 0 or spf == 0:
        raise ValueError("BPB inválido (FAT32)")

    return FAT32BPB(
        bytes_per_sector=bps,
        sectors_per_cluster=spc,
        reserved_sectors=rsv,
        num_fats=nf,
        sectors_per_fat=spf,
        root_cluster=root_cluster if root_cluster != 0 else 2,
        total_sectors=total,
    )

def fat_region_offset(bpb: FAT32BPB) -> int:
    return bpb.reserved_sectors * bpb.bytes_per_sector

def data_region_offset(bpb: FAT32BPB) -> int:
    return (bpb.reserved_sectors + (bpb.num_fats * bpb.sectors_per_fat)) * bpb.bytes_per_sector

def cluster_to_offset(bpb: FAT32BPB, cluster: int) -> int:
    if cluster < 2:
        cluster = 2
    data_off = data_region_offset(bpb)
    return data_off + (cluster - 2) * bpb.cluster_size

def read_fat_entry(reader: RawVolumeReader, bpb: FAT32BPB, cluster: int) -> int:
    fat_off = fat_region_offset(bpb)
    entry_off = fat_off + cluster * 4
    raw = reader.read_at(entry_off, 4)
    val = int.from_bytes(raw, "little") & 0x0FFFFFFF
    return val

def follow_chain(reader: RawVolumeReader, bpb: FAT32BPB, start_cluster: int, max_steps: int = 2_000_000) -> List[int]:
    chain: List[int] = []
    c = start_cluster
    steps = 0
    while c >= 2 and steps < max_steps:
        chain.append(c)
        nxt = read_fat_entry(reader, bpb, c)
        if nxt == 0:
            break
        if nxt >= EOC_MIN:
            break
        c = nxt
        steps += 1
    return chain

def parse_83_name(entry: bytes) -> str:
    name = entry[0:8].decode("ascii", errors="replace").rstrip()
    ext = entry[8:11].decode("ascii", errors="replace").rstrip()
    if ext:
        return f"{name}.{ext}"
    return name

def is_lfn_entry(attr: int) -> bool:
    return (attr & 0x0F) == 0x0F

def lfn_part(entry: bytes) -> str:
    # UTF-16LE chars em três blocos: 1-10, 14-25, 28-31
    def take(off: int, size: int) -> List[int]:
        out = []
        for i in range(off, off + size, 2):
            out.append(int.from_bytes(entry[i:i+2], "little"))
        return out

    chars = take(1, 10) + take(14, 12) + take(28, 4)
    s = ""
    for c in chars:
        if c in (0x0000, 0xFFFF):
            continue
        s += chr(c)
    return s

@dataclass(frozen=True)
class DeletedCandidate:
    name: str
    first_cluster: int
    size: int
    attrs: int
    dir_cluster: int

def list_deleted_candidates_in_dir(reader: RawVolumeReader, bpb: FAT32BPB, dir_cluster: int) -> List[DeletedCandidate]:
    candidates: List[DeletedCandidate] = []
    chain = follow_chain(reader, bpb, dir_cluster)
    lfn_stack: List[str] = []

    for cl in chain:
        off = cluster_to_offset(bpb, cl)
        buf = reader.read_at(off, bpb.cluster_size)

        for i in range(0, len(buf), 32):
            ent = buf[i:i+32]
            if len(ent) < 32:
                continue

            first = ent[0]
            attr = ent[11]

            if first == 0x00:
                lfn_stack = []
                break

            if is_lfn_entry(attr):
                # LFN pode estar marcado como deletado (primeiro byte 0xE5)
                part = lfn_part(ent)
                if part:
                    lfn_stack.append(part)
                continue

            # entrada “normal”
            if first == 0xE5:
                lo = int.from_bytes(ent[26:28], "little")
                hi = int.from_bytes(ent[20:22], "little")
                first_cluster = (hi << 16) | lo
                size = int.from_bytes(ent[28:32], "little")

                if lfn_stack:
                    name = "".join(reversed(lfn_stack)).strip()
                else:
                    name = parse_83_name(ent)

                lfn_stack = []

                # ignora diretórios por enquanto (pode ser expandido)
                is_dir = (attr & 0x10) != 0
                if is_dir:
                    continue

                candidates.append(
                    DeletedCandidate(
                        name=name,
                        first_cluster=first_cluster,
                        size=size,
                        attrs=attr,
                        dir_cluster=dir_cluster,
                    )
                )
            else:
                lfn_stack = []

    return candidates

def detect_fat32(reader: RawVolumeReader) -> bool:
    bs = reader.read_at(0, 512)
    # FAT32 geralmente tem assinatura "FAT32" no offset 82 (0x52)
    sig = bs[82:87]
    return sig.startswith(b"FAT32")

def recover_candidate(
    reader: RawVolumeReader,
    bpb: FAT32BPB,
    cand: DeletedCandidate,
    output_dir: str,
    allowed_exts: List[str],
) -> Optional[Dict[str, Any]]:
    if cand.first_cluster < 2 or cand.size <= 0:
        return None

    ext = os.path.splitext(cand.name)[1].lower().lstrip(".")
    if allowed_exts and ext not in set([e.lower().lstrip(".") for e in allowed_exts]):
        return None

    out_path = os.path.join(output_dir, cand.name)
    base, e = os.path.splitext(out_path)
    n = 1
    while os.path.exists(out_path):
        out_path = f"{base}__{n}{e}"
        n += 1

    # tenta usar cadeia FAT (se ainda existir). Se a FAT estiver “zerada”, assume contíguo.
    chain = follow_chain(reader, bpb, cand.first_cluster)
    bytes_needed = cand.size
    clusters_needed = int(math.ceil(bytes_needed / bpb.cluster_size))

    if len(chain) <= 1:
        # provável FAT limpa; assume contíguo
        chain = [cand.first_cluster + i for i in range(clusters_needed)]

    with open(out_path, "wb") as f:
        remaining = bytes_needed
        for cl in chain:
            if remaining <= 0:
                break
            off = cluster_to_offset(bpb, cl)
            chunk = reader.read_at(off, min(bpb.cluster_size, remaining))
            f.write(chunk)
            remaining -= len(chunk)

    method = "fat32_undelete_chain" if clusters_needed == len(chain) else "fat32_undelete_contiguous"
    return {
        "recovered_path": out_path,
        "method": method,
        "offset": cluster_to_offset(bpb, cand.first_cluster),
        "size_bytes": cand.size,
        "ext": ext,
    }

def recover_deleted_fat32(
    reader: RawVolumeReader,
    output_dir: str,
    selected_exts: List[str],
    progress_cb=None,
) -> List[Dict[str, Any]]:
    bs = reader.read_at(0, 512)
    bpb = parse_bpb(bs)

    total_bytes = bpb.total_sectors * bpb.bytes_per_sector
    if progress_cb:
        progress_cb(processed_bytes=0, total_bytes=total_bytes, message="FAT32: analisando diretório raiz...")

    root = bpb.root_cluster
    candidates = list_deleted_candidates_in_dir(reader, bpb, root)

    if progress_cb:
        progress_cb(processed_bytes=min(total_bytes, 10 * 1024 * 1024), total_bytes=total_bytes, message=f"FAT32: candidatos deletados encontrados: {len(candidates)}")

    results: List[Dict[str, Any]] = []
    processed = 0

    for idx, cand in enumerate(candidates, start=1):
        r = recover_candidate(reader, bpb, cand, output_dir, selected_exts)
        if r:
            results.append(r)

        processed = int((idx / max(1, len(candidates))) * total_bytes)
        if progress_cb:
            progress_cb(processed_bytes=processed, total_bytes=total_bytes, message=f"FAT32: recuperando {idx}/{len(candidates)}")

    if progress_cb:
        progress_cb(processed_bytes=total_bytes, total_bytes=total_bytes, message="FAT32: finalizado.")

    return results