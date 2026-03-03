import os
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

from .device_reader import RawVolumeReader

ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_SECURITY_DESCRIPTOR = 0x50
ATTR_VOLUME_NAME = 0x60
ATTR_VOLUME_INFORMATION = 0x70
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
ATTR_REPARSE_POINT = 0xC0
ATTR_EA_INFORMATION = 0xD0
ATTR_EA = 0xE0
ATTR_LOGGED_UTILITY_STREAM = 0x100
ATTR_END = 0xFFFFFFFF

@dataclass(frozen=True)
class NTFSBoot:
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    mft_lcn: int
    mftmirr_lcn: int
    file_record_size: int
    volume_total_sectors: int

def detect_ntfs(reader: RawVolumeReader) -> bool:
    bs = reader.read_at(0, 512)
    return bs[3:11] == b"NTFS    "

def _u16(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off+2], "little")

def _u32(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off+4], "little")

def _u64(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off+8], "little", signed=False)

def _i8(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off+1], "little", signed=True)

def parse_boot(reader: RawVolumeReader) -> NTFSBoot:
    bs = reader.read_at(0, 512)

    bps = _u16(bs, 11)
    spc_raw = _i8(bs, 13)
    spc = spc_raw if spc_raw > 0 else (1 << (-spc_raw))  # defensive
    cluster_size = bps * spc

    total_sectors = _u64(bs, 40)
    mft_lcn = _u64(bs, 48)
    mftmirr_lcn = _u64(bs, 56)

    frs = _i8(bs, 64)
    if frs < 0:
        file_record_size = 1 << (-frs)
    else:
        file_record_size = frs * cluster_size

    if bps == 0 or spc == 0 or mft_lcn == 0 or file_record_size == 0:
        raise ValueError("Boot NTFS inválido")

    return NTFSBoot(
        bytes_per_sector=bps,
        sectors_per_cluster=spc,
        cluster_size=cluster_size,
        mft_lcn=mft_lcn,
        mftmirr_lcn=mftmirr_lcn,
        file_record_size=file_record_size,
        volume_total_sectors=total_sectors,
    )

def lcn_to_offset(boot: NTFSBoot, lcn: int) -> int:
    return lcn * boot.cluster_size

def _apply_fixup(record: bytearray, bytes_per_sector: int) -> bool:
    """
    NTFS usa fixup array (USA) para proteger setores.
    FILE record header:
    - usa_offset (0x04, uint16)
    - usa_count  (0x06, uint16) -> inclui o USN + 1 por setor
    """
    if record[0:4] != b"FILE":
        return False

    usa_off = int.from_bytes(record[4:6], "little")
    usa_cnt = int.from_bytes(record[6:8], "little")
    if usa_off == 0 or usa_cnt < 2:
        return False

    usa_end = usa_off + usa_cnt * 2
    if usa_end > len(record):
        return False

    usa = record[usa_off:usa_end]
    usn = usa[0:2]
    replacements = [usa[2+i*2:4+i*2] for i in range(usa_cnt - 1)]

    sector_size = bytes_per_sector
    for i, rep in enumerate(replacements):
        pos = (i + 1) * sector_size - 2
        if pos + 2 > len(record):
            return False
        if record[pos:pos+2] != usn:
            return False
        record[pos:pos+2] = rep
    return True

def _parse_attr_header(rec: bytes, off: int) -> Optional[Dict[str, Any]]:
    if off + 4 > len(rec):
        return None
    attr_type = int.from_bytes(rec[off:off+4], "little")
    if attr_type == ATTR_END:
        return None

    if off + 16 > len(rec):
        return None
    attr_len = int.from_bytes(rec[off+4:off+8], "little")
    non_res = rec[off+8]
    name_len = rec[off+9]
    name_off = int.from_bytes(rec[off+10:off+12], "little")
    flags = int.from_bytes(rec[off+12:off+14], "little")
    attr_id = int.from_bytes(rec[off+14:off+16], "little")

    if attr_len <= 0 or off + attr_len > len(rec):
        return None

    hdr = {
        "type": attr_type,
        "len": attr_len,
        "non_res": non_res,
        "name_len": name_len,
        "name_off": name_off,
        "flags": flags,
        "id": attr_id,
        "off": off,
    }

    if non_res == 0:
        # resident
        if off + 24 > len(rec):
            return None
        value_len = int.from_bytes(rec[off+16:off+20], "little")
        value_off = int.from_bytes(rec[off+20:off+22], "little")
        hdr.update({
            "value_len": value_len,
            "value_off": value_off,
        })
    else:
        # non-resident
        if off + 64 > len(rec):
            return None
        start_vcn = int.from_bytes(rec[off+16:off+24], "little")
        last_vcn = int.from_bytes(rec[off+24:off+32], "little")
        run_off = int.from_bytes(rec[off+32:off+34], "little")
        comp_unit = int.from_bytes(rec[off+34:off+36], "little")
        alloc_sz = int.from_bytes(rec[off+40:off+48], "little")
        real_sz = int.from_bytes(rec[off+48:off+56], "little")
        init_sz = int.from_bytes(rec[off+56:off+64], "little")

        hdr.update({
            "start_vcn": start_vcn,
            "last_vcn": last_vcn,
            "run_off": run_off,
            "comp_unit": comp_unit,
            "alloc_sz": alloc_sz,
            "real_sz": real_sz,
            "init_sz": init_sz,
        })
    return hdr

def _parse_runs(run_data: bytes) -> List[Tuple[int, int]]:
    """
    Retorna lista de (lcn, clusters) para Data Runs.
    Cada header byte: low nibble = size len, high nibble = offset len.
    Offset é signed, relativo ao LCN anterior.
    """
    runs: List[Tuple[int, int]] = []
    i = 0
    prev_lcn = 0

    while i < len(run_data):
        head = run_data[i]
        i += 1
        if head == 0x00:
            break

        len_len = head & 0x0F
        off_len = (head >> 4) & 0x0F

        if i + len_len + off_len > len(run_data):
            break

        clen = int.from_bytes(run_data[i:i+len_len], "little", signed=False)
        i += len_len

        coff_raw = int.from_bytes(run_data[i:i+off_len], "little", signed=False)
        # sign-extend for offset
        if off_len > 0 and (run_data[i + off_len - 1] & 0x80):
            coff = coff_raw - (1 << (off_len * 8))
        else:
            coff = coff_raw
        i += off_len

        lcn = prev_lcn + coff
        prev_lcn = lcn

        if clen > 0:
            runs.append((lcn, clen))

    return runs

def _best_filename_from_record(rec: bytes, attrs: List[Dict[str, Any]]) -> Optional[str]:
    # Prefer WIN32 name (namespace 1) and longer names
    best = None
    best_score = -1
    for a in attrs:
        if a["type"] != ATTR_FILE_NAME:
            continue
        if a["non_res"] != 0:
            continue
        voff = a["off"] + a["value_off"]
        vlen = a["value_len"]
        if voff + vlen > len(rec) or vlen < 0x42:
            continue
        val = rec[voff:voff+vlen]
        name_len = val[64]
        name_ns = val[65]  # 0=POSIX, 1=WIN32, 2=DOS, 3=WIN32&DOS
        name_raw = val[66:66 + name_len * 2]
        try:
            name = name_raw.decode("utf-16le", errors="ignore")
        except Exception:
            continue
        score = 0
        if name_ns in (1, 3):
            score += 10
        score += len(name)
        if score > best_score:
            best_score = score
            best = name
    return best

def _find_data_attr(rec: bytes, attrs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    # prefer unnamed $DATA
    unnamed = None
    named = None
    for a in attrs:
        if a["type"] != ATTR_DATA:
            continue
        if a["name_len"] == 0:
            unnamed = a
            break
        named = a
    return unnamed or named

def _ext_allowed(name: str, allowed_exts: List[str]) -> bool:
    if not allowed_exts:
        return True
    ext = os.path.splitext(name)[1].lower().lstrip(".")
    allowed = {e.lower().lstrip(".") for e in allowed_exts}
    return ext in allowed

def _safe_output_path(output_dir: str, filename: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    filename = filename.replace("\\", "_").replace("/", "_").strip()
    if not filename:
        filename = "recuperado.bin"
    out = os.path.join(output_dir, filename)
    base, ext = os.path.splitext(out)
    n = 1
    while os.path.exists(out):
        out = f"{base}__{n}{ext}"
        n += 1
    return out

def _read_file_record(reader: RawVolumeReader, boot: NTFSBoot, record_idx: int) -> Optional[bytes]:
    mft_off = lcn_to_offset(boot, boot.mft_lcn)
    rec_off = mft_off + record_idx * boot.file_record_size
    raw = reader.read_at(rec_off, boot.file_record_size)
    if len(raw) != boot.file_record_size:
        return None
    buf = bytearray(raw)
    if buf[0:4] != b"FILE":
        return None
    if not _apply_fixup(buf, boot.bytes_per_sector):
        return None
    return bytes(buf)

def _is_deleted_record(rec: bytes) -> bool:
    # FILE record flags at offset 0x16 (uint16): bit0=in use, bit1=directory
    if len(rec) < 0x18:
        return False
    flags = int.from_bytes(rec[0x16:0x18], "little")
    in_use = (flags & 0x0001) != 0
    return not in_use

def _is_directory_record(rec: bytes) -> bool:
    flags = int.from_bytes(rec[0x16:0x18], "little")
    return (flags & 0x0002) != 0

def _parse_attributes(rec: bytes) -> List[Dict[str, Any]]:
    attrs: List[Dict[str, Any]] = []
    # attribute offset at 0x14 (uint16)
    attr_off = int.from_bytes(rec[0x14:0x16], "little")
    off = attr_off
    # iterate until end marker
    while off + 4 <= len(rec):
        hdr = _parse_attr_header(rec, off)
        if not hdr:
            break
        attrs.append(hdr)
        off = off + hdr["len"]
    return attrs

def _recover_ntfs_data(
    reader: RawVolumeReader,
    boot: NTFSBoot,
    rec: bytes,
    data_attr: Dict[str, Any],
    out_path: str,
) -> Optional[Dict[str, Any]]:
    if data_attr["non_res"] == 0:
        # resident data
        voff = data_attr["off"] + data_attr["value_off"]
        vlen = data_attr["value_len"]
        if voff + vlen > len(rec):
            return None
        with open(out_path, "wb") as f:
            f.write(rec[voff:voff+vlen])
        return {
            "recovered_path": out_path,
            "method": "ntfs_undelete_resident",
            "offset": None,
            "size_bytes": vlen,
        }

    # non-resident: parse runs
    run_off = data_attr["off"] + data_attr["run_off"]
    if run_off > len(rec):
        return None
    # runs end before attribute end
    attr_end = data_attr["off"] + data_attr["len"]
    run_data = rec[run_off:attr_end]
    runs = _parse_runs(run_data)
    real_sz = int(data_attr.get("real_sz", 0))

    if not runs or real_sz <= 0:
        return None

    with open(out_path, "wb") as f:
        remaining = real_sz
        for (lcn, clen) in runs:
            if remaining <= 0:
                break
            # sparse run: lcn == 0 and it indicates holes (we write zeros)
            if lcn == 0:
                to_write = min(remaining, clen * boot.cluster_size)
                f.write(b"\x00" * to_write)
                remaining -= to_write
                continue

            off = lcn_to_offset(boot, lcn)
            to_read = min(remaining, clen * boot.cluster_size)
            chunk = reader.read_at(off, to_read)
            f.write(chunk)
            remaining -= len(chunk)

    first_lcn = runs[0][0]
    return {
        "recovered_path": out_path,
        "method": "ntfs_undelete_nonresident_runs",
        "offset": lcn_to_offset(boot, first_lcn) if first_lcn else None,
        "size_bytes": real_sz,
    }

def recover_deleted_ntfs(
    reader: RawVolumeReader,
    output_dir: str,
    selected_exts: List[str],
    progress_cb=None,
) -> List[Dict[str, Any]]:
    boot = parse_boot(reader)
    total_bytes = boot.volume_total_sectors * boot.bytes_per_sector

    if progress_cb:
        progress_cb(processed_bytes=0, total_bytes=total_bytes, message="NTFS: lendo $MFT...")

    # varre um range inicial de registros da MFT (ajustável)
    # Para ficar prático e não infinito: começamos com 200k registros.
    max_records = 200_000

    results: List[Dict[str, Any]] = []
    found_deleted = 0
    processed = 0

    for idx in range(max_records):
        rec = _read_file_record(reader, boot, idx)
        if not rec:
            # não necessariamente fim; apenas pula
            processed = int((idx / max_records) * total_bytes)
            if progress_cb and idx % 1000 == 0:
                progress_cb(processed_bytes=processed, total_bytes=total_bytes, message=f"NTFS: varrendo MFT {idx}/{max_records}")
            continue

        if _is_directory_record(rec):
            processed = int((idx / max_records) * total_bytes)
            if progress_cb and idx % 1000 == 0:
                progress_cb(processed_bytes=processed, total_bytes=total_bytes, message=f"NTFS: varrendo MFT {idx}/{max_records}")
            continue

        if not _is_deleted_record(rec):
            processed = int((idx / max_records) * total_bytes)
            if progress_cb and idx % 1000 == 0:
                progress_cb(processed_bytes=processed, total_bytes=total_bytes, message=f"NTFS: varrendo MFT {idx}/{max_records}")
            continue

        attrs = _parse_attributes(rec)
        name = _best_filename_from_record(rec, attrs)
        if not name:
            name = f"ntfs_rec_{idx}.bin"

        if not _ext_allowed(name, selected_exts):
            processed = int((idx / max_records) * total_bytes)
            if progress_cb and idx % 1000 == 0:
                progress_cb(processed_bytes=processed, total_bytes=total_bytes, message=f"NTFS: filtrando {idx}/{max_records}")
            continue

        data_attr = _find_data_attr(rec, attrs)
        if not data_attr:
            processed = int((idx / max_records) * total_bytes)
            if progress_cb and idx % 1000 == 0:
                progress_cb(processed_bytes=processed, total_bytes=total_bytes, message=f"NTFS: sem $DATA {idx}/{max_records}")
            continue

        out_path = _safe_output_path(output_dir, name)
        recovered = _recover_ntfs_data(reader, boot, rec, data_attr, out_path)
        if recovered:
            found_deleted += 1
            recovered.update({
                "ext": os.path.splitext(name)[1].lower().lstrip("."),
                "mft_record": idx,
            })
            results.append(recovered)

        processed = int((idx / max_records) * total_bytes)
        if progress_cb and idx % 1000 == 0:
            progress_cb(
                processed_bytes=processed,
                total_bytes=total_bytes,
                message=f"NTFS: recuperados {found_deleted} (MFT {idx}/{max_records})"
            )

    if progress_cb:
        progress_cb(processed_bytes=total_bytes, total_bytes=total_bytes, message=f"NTFS: finalizado. Recuperados: {len(results)}")

    return results