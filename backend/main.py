from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from scanner.lab_scanner import LabScanner


app = FastAPI(
    title="Authorized Web Security Scanner",
    version="0.7.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()

        if any(char in value for char in "[]()"):
            raise ValueError(
                "URL must be a plain URL, not a Markdown link"
            )

        if not (
            value.startswith("http://")
            or value.startswith("https://")
        ):
            raise ValueError(
                "URL must start with http:// or https://"
            )

        return value


class Finding(BaseModel):
    title: str
    severity: str
    description: str
    evidence: str
    tool: str


scans: dict[str, dict] = {}


def add_finding(
    scan_id: str,
    finding: dict,
) -> None:
    scans[scan_id]["findings"].append(
        Finding(**finding).model_dump()
    )


async def run_scan(scan_id: str):
    scan = scans[scan_id]

    try:
        scanner = LabScanner()
        findings = await scanner.scan(scan["target"])

        for finding in findings:
            add_finding(scan_id, finding)

        scan["status"] = "completed"

    except Exception as exc:
        scan["status"] = "failed"
        scan["error"] = str(exc)


@app.get("/")
def home():
    return {
        "status": "ok",
        "message": "Security Scanner API is running",
    }


@app.post("/scan")
def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
):
    scan_id = str(uuid4())

    scans[scan_id] = {
        "scan_id": scan_id,
        "target": request.url,
        "status": "queued",
        "findings": [],
    }

    background_tasks.add_task(run_scan, scan_id)

    return scans[scan_id]


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return scan


@app.get("/scan/{scan_id}/findings")
def get_findings(
    scan_id: str,
    severity: str | None = Query(default=None),
):
    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = scan["findings"]

    if severity:
        findings = [
            finding
            for finding in findings
            if finding["severity"] == severity
        ]

    return {
        "scan_id": scan_id,
        "count": len(findings),
        "findings": findings,
    }
