# PARA
import os
import sys
import threading
import traceback
import webbrowser
import tkinter as tk
from tkinter import filedialog

from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask import send_from_directory


from recover.jobs import create_job, get_job
from recover.carver import carve_file
from recover.folder_recover import recover_from_folder
from recover.undelete_engine import recover_deleted_from_volume
from recover.audit import ensure_dir, write_csv, write_json


def resource_path(*parts):
    """
    Resolve paths tanto no modo dev quanto no modo empacotado (PyInstaller).
    """
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


TEMPLATE_DIR = resource_path("templates")
STATIC_DIR = resource_path("static")

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR,
    static_url_path="/static",
)

USER_HOME = os.path.expanduser("~")
BASE_OUTPUT = os.path.join(USER_HOME, "RecoveryTool", "output")
ensure_dir(BASE_OUTPUT)

@app.get("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, "favicon.ico")

def run_job_undelete(job_id: str, drive_path: str, selected_exts):
    job = get_job(job_id)
    if not job:
        return

    try:
        with job.lock:
            job.state = "running"
            job.message = "Iniciando undelete (leitura do volume em baixo nível)..."
            job.progress_percent = 0.0
            job.processed_bytes = 0
            job.total_bytes = 0
            job.found_files = 0
            job.total_files = 0

        job_dir = os.path.join(job.output_dir, job.job_id)
        ensure_dir(job_dir)

        def progress_cb(processed_bytes=None, total_bytes=None, message=None, found_files=None, total_files=None):
            with job.lock:
                if processed_bytes is not None:
                    job.processed_bytes = int(processed_bytes)
                if total_bytes is not None:
                    job.total_bytes = int(total_bytes)

                if message is not None:
                    job.message = str(message)

                if found_files is not None:
                    job.found_files = int(found_files)

                if total_files is not None:
                    job.total_files = int(total_files)

                if job.total_bytes > 0:
                    job.progress_percent = round((job.processed_bytes / job.total_bytes) * 100, 2)
                else:
                    job.progress_percent = 0.0

        rows = recover_deleted_from_volume(
            drive_path=drive_path,
            output_dir=job_dir,
            selected_exts=selected_exts,
            progress_cb=progress_cb,
        )

        csv_path = os.path.join(job_dir, "relatorio_undelete.csv")
        json_path = os.path.join(job_dir, "relatorio_undelete.json")
        write_csv(csv_path, rows)
        write_json(json_path, rows)

        with job.lock:
            job.state = "done"
            job.message = "Undelete concluído. Relatórios gerados e arquivos recuperados (quando possível)."
            job.report_paths = {"csv": csv_path, "json": json_path}

    except Exception as e:
        err = traceback.format_exc()

        with job.lock:
            job.state = "error"
            job.error = err

            if isinstance(e, PermissionError):
                job.message = "Permissão insuficiente: execute o sistema como Administrador para recuperar deletados na unidade."
            else:
                job.message = "Falha ao executar o undelete."


def _pick_file_dialog(title: str, filetypes):
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askopenfilename(title=title, filetypes=filetypes)
    root.destroy()
    return path


def _pick_directory_dialog(title: str):
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askdirectory(title=title)
    root.destroy()
    return path


def run_job_carving(job_id: str, selected_exts):
    job = get_job(job_id)
    if not job:
        return

    try:
        with job.lock:
            job.state = "running"
            job.message = "Analisando a imagem/disco e iniciando a varredura (carving)..."

        job_dir = os.path.join(job.output_dir, job.job_id)
        ensure_dir(job_dir)

        def progress_cb(processed_bytes=None, total_bytes=None, found_files=None):
            with job.lock:
                if processed_bytes is not None:
                    job.processed_bytes = processed_bytes
                if total_bytes is not None:
                    job.total_bytes = total_bytes
                if job.total_bytes > 0:
                    job.progress_percent = round((job.processed_bytes / job.total_bytes) * 100, 2)
                if found_files is not None:
                    job.found_files = found_files

        rows = carve_file(
            source_path=job.source_path,
            output_dir=job_dir,
            selected_exts=selected_exts,
            progress_cb=progress_cb,
        )

        csv_path = os.path.join(job_dir, "relatorio_recuperacao.csv")
        json_path = os.path.join(job_dir, "relatorio_recuperacao.json")
        write_csv(csv_path, rows)
        write_json(json_path, rows)

        with job.lock:
            job.state = "done"
            job.message = "Recuperação concluída. Relatórios gerados e arquivos exportados."
            job.report_paths = {"csv": csv_path, "json": json_path}

    except Exception as e:
        with job.lock:
            job.state = "error"
            job.error = str(e)
            job.message = "Falha ao executar a recuperação (carving)."


def run_job_folder(job_id: str, selected_exts):
    job = get_job(job_id)
    if not job:
        return

    try:
        with job.lock:
            job.state = "running"
            job.message = "Preparando varredura: contabilizando arquivos elegíveis..."

        job_dir = os.path.join(job.output_dir, job.job_id)
        ensure_dir(job_dir)

        def progress_cb(found_files=None, total_files=None, stage=None, scanned_files=None, processed_bytes=None, total_bytes=None):
            with job.lock:
                if total_files is not None:
                    job.total_files = int(total_files)

                if stage == "counting":
                    job.message = f"Contabilizando arquivos… (verificados: {scanned_files or 0} | elegíveis: {job.total_files})"
                    job.progress_percent = 0.0
                    job.found_files = 0
                    return

                if stage == "counting_done":
                    job.message = f"Contagem concluída. Iniciando exportação… (total elegíveis: {job.total_files})"
                    job.progress_percent = 0.0
                    job.found_files = 0
                    return

                if found_files is not None:
                    job.found_files = int(found_files)

                if job.total_files > 0:
                    job.progress_percent = round((job.found_files / job.total_files) * 100, 2)
                    job.message = f"Exportando arquivos… ({job.found_files}/{job.total_files})"
                else:
                    job.progress_percent = 0.0
                    job.message = "Nenhum arquivo elegível encontrado para as extensões selecionadas."

        rows = recover_from_folder(
            source_dir=job.source_path,
            output_dir=job_dir,
            selected_exts=selected_exts,
            progress_cb=progress_cb,
        )

        csv_path = os.path.join(job_dir, "relatorio_exportacao.csv")
        json_path = os.path.join(job_dir, "relatorio_exportacao.json")
        write_csv(csv_path, rows)
        write_json(json_path, rows)

        with job.lock:
            job.state = "done"
            job.message = "Exportação concluída. Relatórios gerados."
            job.report_paths = {"csv": csv_path, "json": json_path}

    except Exception as e:
        with job.lock:
            job.state = "error"
            job.error = str(e)
            job.message = "Falha ao executar a exportação da pasta."


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/pick-source")
def api_pick_source():
    path = _pick_file_dialog(
        title="Selecionar imagem/backup do disco",
        filetypes=[
            ("Imagens de disco", "*.dd *.img *.iso *.bin"),
            ("Todos os arquivos", "*.*"),
        ],
    )
    return jsonify({"path": path})


@app.get("/api/pick-source-dir")
def api_pick_source_dir():
    path = _pick_directory_dialog(title="Selecionar pasta de origem")
    return jsonify({"path": path})


@app.get("/api/pick-dest")
def api_pick_dest():
    path = _pick_directory_dialog(title="Selecionar pasta de destino")
    return jsonify({"path": path})


import ctypes
from ctypes import wintypes


def _windows_list_drives():
    """
    Retorna lista de unidades lógicas (C:, D:, E:...) com informações básicas.
    Não exige admin.
    """
    drives = []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    GetLogicalDrives = kernel32.GetLogicalDrives
    GetLogicalDrives.restype = wintypes.DWORD

    GetDriveTypeW = kernel32.GetDriveTypeW
    GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    GetDriveTypeW.restype = wintypes.UINT

    GetVolumeInformationW = kernel32.GetVolumeInformationW
    GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR, wintypes.DWORD
    ]
    GetVolumeInformationW.restype = wintypes.BOOL

    mask = GetLogicalDrives()
    for i in range(26):
        if not (mask & (1 << i)):
            continue

        letter = chr(ord("A") + i)
        root = f"{letter}:\\"

        dtype = GetDriveTypeW(root)
        type_map = {
            0: "UNKNOWN",
            1: "NO_ROOT_DIR",
            2: "REMOVABLE",
            3: "FIXED",
            4: "REMOTE",
            5: "CDROM",
            6: "RAMDISK",
        }
        drive_type = type_map.get(dtype, "UNKNOWN")

        vol_name_buf = ctypes.create_unicode_buffer(261)
        fs_name_buf = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD(0)
        max_comp_len = wintypes.DWORD(0)
        fs_flags = wintypes.DWORD(0)

        ok = GetVolumeInformationW(
            root,
            vol_name_buf, 260,
            ctypes.byref(serial),
            ctypes.byref(max_comp_len),
            ctypes.byref(fs_flags),
            fs_name_buf, 260
        )

        label = vol_name_buf.value if ok else ""
        fs = fs_name_buf.value if ok else ""

        drives.append({
            "root": root,
            "letter": letter,
            "type": drive_type,
            "label": label,
            "fs": fs,
        })

    drives.sort(key=lambda d: d["letter"])
    return drives


@app.get("/api/drives")
def api_drives():
    if os.name != "nt":
        return jsonify({"drives": []})
    return jsonify({"drives": _windows_list_drives()})


@app.post("/start")
def start():
    origin_mode = request.form.get("origin_mode", "disk_image").strip()

    source_path = request.form.get("source_path", "").strip()
    source_dir = request.form.get("source_dir", "").strip()
    drive_path = request.form.get("drive_path", "").strip()

    output_dir = request.form.get("output_dir", "").strip() or BASE_OUTPUT
    exts = request.form.getlist("exts")

    if not os.path.isdir(output_dir):
        return render_template("index.html", error="Diretório de destino inválido. Selecione uma pasta válida.")

    # MODO UNDELETE: usa unidade (ex.: E:\) e leitura RAW (admin)
    if origin_mode == "undelete":
        if not drive_path:
            return render_template("index.html", error="Selecione uma unidade (ex.: E:\\) para recuperar deletados.")

        job = create_job(source_path=drive_path, output_dir=output_dir)
        t = threading.Thread(target=run_job_undelete, args=(job.job_id, drive_path, exts), daemon=True)
        t.start()
        return redirect(url_for("status_page", job_id=job.job_id))

    # MODO PASTA: permite usar uma unidade (ex.: E:\) como pasta raiz
    if origin_mode == "folder":
        if not source_dir:
            if drive_path:
                source_dir = drive_path

        if not source_dir:
            return render_template("index.html", error="Selecione uma pasta ou unidade de origem.")
        if not os.path.isdir(source_dir):
            return render_template("index.html", error="Origem inválida. Selecione novamente.")

        job = create_job(source_path=source_dir, output_dir=output_dir)
        t = threading.Thread(target=run_job_folder, args=(job.job_id, exts), daemon=True)
        t.start()
        return redirect(url_for("status_page", job_id=job.job_id))

    # MODO IMAGEM/DISCO (carving): trabalha com arquivo de imagem (dd/img/iso)
    if not source_path:
        return render_template(
            "index.html",
            error="Selecione uma imagem/backup do disco (.dd/.img/.iso). Para recuperar deletados direto da unidade, selecione o modo Undelete."
        )
    if not os.path.exists(source_path):
        return render_template("index.html", error="Arquivo de origem não encontrado. Selecione novamente.")

    job = create_job(source_path=source_path, output_dir=output_dir)
    t = threading.Thread(target=run_job_carving, args=(job.job_id, exts), daemon=True)
    t.start()
    return redirect(url_for("status_page", job_id=job.job_id))


@app.get("/status/<job_id>")
def status_page(job_id):
    job = get_job(job_id)
    if not job:
        return render_template("index.html", error="Job não encontrado ou expirado. Inicie uma nova recuperação.")
    return render_template("status.html", job=job, job_id=job_id)


@app.get("/api/status/<job_id>")
def api_status(job_id):
    job = get_job(job_id)
    if not job:
        return jsonify({
            "state": "error",
            "message": "Job não encontrado",
            "error": "Job não encontrado",
            "progress_percent": 0,
            "processed_bytes": 0,
            "total_bytes": 0,
            "found_files": 0,
            "total_files": 0,
            "output_dir": None,
            "report_paths": {}
        }), 404

    with job.lock:
        return jsonify({
            "job_id": job.job_id,
            "state": job.state,
            "message": job.message,
            "error": job.error,
            "progress_percent": job.progress_percent,
            "processed_bytes": job.processed_bytes,
            "total_bytes": job.total_bytes,
            "found_files": job.found_files,
            "total_files": job.total_files,
            "output_dir": job.output_dir,
            "report_paths": job.report_paths,
        })


if __name__ == "__main__":
    url = "http://127.0.0.1:5050/"
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=5050, debug=False, threaded=True)