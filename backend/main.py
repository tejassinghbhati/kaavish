import uuid
import asyncio
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, HttpUrl

from core.scanner import profile_target
from core.executor import run_scan, ScanResult, ScanStatus
from core.reporter import generate_markdown_report, generate_pdf_report


# In-memory store for MVP — swap for PostgreSQL in week 3-4
_scans: dict[str, ScanResult] = {}
_scan_locks: dict[str, asyncio.Lock] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="Kaavish",
    description="Automated red teaming for AI systems.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ──────────────────────────────────────────────

class ScanRequest(BaseModel):
    target_endpoint: str
    headers: dict[str, str] = {}
    # Optional: skip profiling and declare the target type directly
    force_agent_attacks: bool = False


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    is_vulnerable: bool | None = None
    findings_count: int | None = None
    critical: int | None = None
    high: int | None = None
    duration_ms: int | None = None


# ── Background scan runner ─────────────────────────────────────────────────

async def _execute_scan(scan_id: str, request: ScanRequest) -> None:
    try:
        profile = await profile_target(request.target_endpoint, request.headers)

        if request.force_agent_attacks:
            profile.has_tools = True

        result = await run_scan(scan_id, profile)
        _scans[scan_id] = result
    except Exception as exc:
        _scans[scan_id] = ScanResult(
            scan_id=scan_id,
            target_endpoint=request.target_endpoint,
            status=ScanStatus.FAILED,
        )


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": "0.1.0"}


@app.post("/scans", response_model=ScanResponse, status_code=202)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
) -> ScanResponse:
    scan_id = str(uuid.uuid4())
    # Placeholder so status checks don't 404 immediately
    _scans[scan_id] = ScanResult(
        scan_id=scan_id,
        target_endpoint=request.target_endpoint,
        status=ScanStatus.QUEUED,
    )
    background_tasks.add_task(_execute_scan, scan_id, request)
    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Scan started. Poll /scans/{scan_id}/status for progress.",
    )


@app.get("/scans/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str) -> ScanStatusResponse:
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatusResponse(
        scan_id=scan_id,
        status=scan.status.value,
        is_vulnerable=scan.is_vulnerable if scan.status == ScanStatus.COMPLETE else None,
        findings_count=len(scan.findings) if scan.status == ScanStatus.COMPLETE else None,
        critical=scan.critical_count if scan.status == ScanStatus.COMPLETE else None,
        high=scan.high_count if scan.status == ScanStatus.COMPLETE else None,
        duration_ms=scan.duration_ms if scan.status == ScanStatus.COMPLETE else None,
    )


@app.get("/scans/{scan_id}/results")
async def get_scan_results(scan_id: str) -> dict:
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETE:
        raise HTTPException(status_code=425, detail=f"Scan is {scan.status.value}")
    return scan.to_dict()


@app.get("/scans/{scan_id}/report.md")
async def get_markdown_report(scan_id: str) -> Response:
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETE:
        raise HTTPException(status_code=425, detail=f"Scan is {scan.status.value}")

    md = generate_markdown_report(scan)
    return Response(content=md, media_type="text/markdown")


@app.get("/scans/{scan_id}/report.pdf")
async def get_pdf_report(scan_id: str) -> Response:
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETE:
        raise HTTPException(status_code=425, detail=f"Scan is {scan.status.value}")

    pdf = generate_pdf_report(scan)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=kaavish-report-{scan_id[:8]}.pdf"},
    )


@app.get("/scans")
async def list_scans() -> list[dict]:
    return [
        {
            "scan_id": s.scan_id,
            "target": s.target_endpoint,
            "status": s.status.value,
            "findings": len(s.findings),
            "critical": s.critical_count,
        }
        for s in _scans.values()
    ]
