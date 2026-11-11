"""Local web app: program dashboard and scope guard API.

Run with:  .venv\\Scripts\\python.exe -m uvicorn eeaao.app:app --port 8765
It listens on 127.0.0.1 only and refuses requests addressed to any other host.
"""
from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import db
from .bots import catalog, runner
from .scope import ScopeGuard

STATIC = Path(__file__).resolve().parent / "static"
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init()
    yield


app = FastAPI(title="Everything Everywhere All at Once", lifespan=lifespan)
# Blocks DNS-rebinding: a web page cannot reach this API under another hostname.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])


class ProgramIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(default="", max_length=500)
    in_scope: str = Field(default="", max_length=100_000)
    out_of_scope: str = Field(default="", max_length=100_000)
    rate_limit: float = Field(default=5, gt=0, le=1000)  # requests per second
    headers: dict[str, str] = Field(default_factory=dict)
    automation_allowed: bool = False
    notes: str = Field(default="", max_length=20_000)
    excluded_types: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("excluded_types")
    @classmethod
    def _known_types(cls, value: list[str]) -> list[str]:
        unknown = set(value) - set(catalog.finding_types())
        if unknown:
            raise ValueError(f"unknown finding types: {', '.join(sorted(unknown))}")
        return sorted(set(value))

    @field_validator("name", "url")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()

    @field_validator("url")
    @classmethod
    def _http_url(cls, value: str) -> str:
        if value and (urlsplit(value).scheme not in ("http", "https")
                      or not urlsplit(value).netloc):
            raise ValueError("program link must start with http:// or https://")
        return value

    @field_validator("headers")
    @classmethod
    def _safe_headers(cls, value: dict[str, str]) -> dict[str, str]:
        for name, content in value.items():
            if not _HEADER_NAME.match(name):
                raise ValueError(f"'{name}' is not a valid header name")
            if re.search(r"[\r\n\x00]", content):
                raise ValueError(f"header '{name}' contains a line break")
        return value


class ScopeText(BaseModel):
    in_scope: str = ""
    out_of_scope: str = ""


class ScopeCheck(BaseModel):
    targets: list[str] = Field(max_length=5000)


def _guard(program: dict) -> ScopeGuard:
    return ScopeGuard(program["in_scope"], program["out_of_scope"],
                      program["automation_allowed"])


def _present(program: dict) -> dict:
    guard = _guard(program)
    return dict(program,
                in_rules=[rule.raw for rule in guard.allow],
                out_rules=[rule.raw for rule in guard.deny],
                scope_errors=guard.errors)


def _require(program_id: int) -> dict:
    program = db.get_program(program_id)
    if program is None:
        raise HTTPException(404, "Program not found")
    return program


def _validated(body: ProgramIn) -> dict:
    data = body.model_dump()
    guard = _guard(data)
    if guard.errors:
        raise HTTPException(422, {"message": "Some scope entries could not be read.",
                                  "scope_errors": guard.errors})
    if not guard.allow:
        raise HTTPException(422, {"message": "Add at least one in-scope entry.",
                                  "scope_errors": []})
    return data


@app.get("/api/programs")
def list_programs():
    return [_present(program) for program in db.list_programs()]


@app.post("/api/programs", status_code=201)
def create_program(body: ProgramIn):
    return _present(db.get_program(db.create_program(_validated(body))))


@app.get("/api/programs/{program_id}")
def get_program(program_id: int):
    return _present(_require(program_id))


@app.put("/api/programs/{program_id}")
def update_program(program_id: int, body: ProgramIn):
    _require(program_id)
    db.update_program(program_id, _validated(body))
    return _present(db.get_program(program_id))


@app.delete("/api/programs/{program_id}", status_code=204)
def delete_program(program_id: int):
    _require(program_id)
    if runner.active_run(program_id):
        raise HTTPException(409, "A run is in progress for this program. Stop it first.")
    db.delete_program(program_id)


@app.get("/api/programs/{program_id}/results")
def result_counts(program_id: int):
    _require(program_id)
    return db.result_counts(program_id)


@app.delete("/api/programs/{program_id}/results")
def clear_results(program_id: int):
    """Delete findings, leads, inventory and saved responses; keep the program."""
    _require(program_id)
    if runner.active_run(program_id):
        raise HTTPException(409, "A run is in progress for this program. Stop it or wait "
                                 "for it to finish before clearing its results.")
    return {"removed": db.clear_results(program_id)}


@app.post("/api/scope/validate")
def validate_scope(body: ScopeText):
    """Live feedback for the program form: which entries the guard understands."""
    guard = ScopeGuard(body.in_scope, body.out_of_scope)
    return {"in_rules": [rule.raw for rule in guard.allow],
            "out_rules": [rule.raw for rule in guard.deny],
            "scope_errors": guard.errors}


@app.post("/api/programs/{program_id}/scope-check")
def scope_check(program_id: int, body: ScopeCheck):
    """Ask the guard about targets. 'allowed' is the scope answer; 'automated'
    is what a tool run would be permitted to touch."""
    guard = _guard(_require(program_id))
    results = []
    for target in body.targets:
        if not target.strip():
            continue
        decision = guard.check(target).as_dict()
        decision["automated"] = guard.check_automated(target).allowed
        results.append(decision)
    return {"automation_allowed": guard.automation_allowed, "results": results}


# ---------- bots ----------

class RunIn(BaseModel):
    department: str
    bots: list[str] | None = None
    options: dict[str, int | bool] = Field(default_factory=dict)


class StatusIn(BaseModel):
    status: str = Field(pattern="^(new|reviewed|dismissed)$")


class TokenIn(BaseModel):
    token: str = Field(min_length=10, max_length=300, pattern=r"^[A-Za-z0-9_\-]+$")


@app.get("/api/catalog")
def get_catalog():
    built = {d: set(bots) for d, bots in runner.IMPLEMENTED.items()}
    departments = catalog.public_catalog()
    for dept in departments:
        dept["runnable"] = dept["id"] in built
    return departments


@app.post("/api/programs/{program_id}/runs", status_code=201)
async def start_run(program_id: int, body: RunIn):
    program = _require(program_id)
    try:
        run_id = runner.start(program, body.department, body.bots, body.options)
    except runner.RunRefused as exc:
        raise HTTPException(409, str(exc)) from None
    return db.get_run(run_id)


@app.get("/api/programs/{program_id}/runs")
def list_runs(program_id: int):
    _require(program_id)
    return {"active": runner.active_run(program_id), "runs": db.list_runs(program_id)}


@app.get("/api/runs/{run_id}")
def get_run(run_id: int, after: int = 0):
    run = db.get_run(run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    return dict(run, events=db.list_events(run_id, after))


@app.post("/api/runs/{run_id}/stop")
def stop_run(run_id: int):
    return {"stopping": runner.stop(run_id)}


@app.get("/api/programs/{program_id}/findings")
def list_findings(program_id: int, kind: str = "finding"):
    program = _require(program_id)
    excluded = set(program["excluded_types"])
    labels = catalog.finding_types()
    items = db.list_findings(program_id, "lead" if kind == "lead" else "finding")
    for item in items:
        item["excluded"] = item["type"] in excluded
        item["type_label"] = labels.get(item["type"], {}).get("label", item["type"])
    return items


@app.patch("/api/findings/{finding_id}")
def set_finding_status(finding_id: int, body: StatusIn):
    if not db.set_finding_status(finding_id, body.status):
        raise HTTPException(404, "Finding not found")
    return {"ok": True}


@app.get("/api/programs/{program_id}/assets")
def list_assets(program_id: int, kind: str = "", q: str = "", limit: int = 100,
                offset: int = 0):
    _require(program_id)
    total, items = db.search_assets(program_id, kind or None, q[:200],
                                    max(1, min(limit, 500)), max(0, offset))
    return {"total": total, "counts": db.asset_counts(program_id), "items": items}


@app.get("/api/programs/{program_id}/requests")
def list_requests(program_id: int, limit: int = 100, offset: int = 0, run_id: int = 0):
    _require(program_id)
    total, items = db.list_requests(program_id, max(1, min(limit, 500)), max(0, offset),
                                    run_id or None)
    return {"total": total, "items": items}


@app.get("/api/settings")
def get_settings():
    return {"github_token_set": bool(db.get_setting("github_token")),
            "github_token_from_env": bool(os.environ.get("GITHUB_TOKEN"))}


@app.put("/api/settings/github-token")
def set_github_token(body: TokenIn):
    db.set_setting("github_token", body.token)
    return get_settings()


@app.delete("/api/settings/github-token")
def delete_github_token():
    db.set_setting("github_token", None)
    return get_settings()


@app.get("/")
def index():
    """The page, with each script and stylesheet address carrying the file's
    current version, so a browser can never keep running old code."""
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    for name in ("app.js", "style.css"):
        version = int((STATIC / name).stat().st_mtime)
        html = html.replace(f"/static/{name}?v=dev", f"/static/{name}?v={version}")
    return HTMLResponse(html, headers={"Cache-Control": "no-cache"})


@app.middleware("http")
async def revalidate_static(request, call_next):
    """Browsers must ask before reusing a cached copy of the app's own files."""
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-cache"
    return response


app.mount("/static", StaticFiles(directory=STATIC), name="static")
