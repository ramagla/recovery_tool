import threading
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional, Any

@dataclass
class JobStatus:
    job_id: str
    source_path: str
    output_dir: str

    state: str = "queued"  # queued | running | done | error
    progress_percent: float = 0.0

    processed_bytes: int = 0
    total_bytes: int = 0

    found_files: int = 0
    total_files: int = 0

    message: str = ""
    error: Optional[str] = None
    report_paths: Dict[str, str] = field(default_factory=dict)
    lock: Any = field(default_factory=threading.Lock)

JOBS: Dict[str, JobStatus] = {}

def create_job(source_path: str, output_dir: str) -> JobStatus:
    job_id = uuid.uuid4().hex
    job = JobStatus(job_id=job_id, source_path=source_path, output_dir=output_dir)
    JOBS[job_id] = job
    return job

def get_job(job_id: str) -> Optional[JobStatus]:
    return JOBS.get(job_id)