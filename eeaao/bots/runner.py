"""Starts, tracks and stops department runs inside the app's event loop."""
from __future__ import annotations

import asyncio
import traceback

from .. import db
from ..scope import ScopeGuard
from . import catalog
from .base import BotContext, RunShared
from .net import DnsClient, OutOfScope, SourceClient, TargetClient, TlsClient
from .content import BOTS as CONTENT_BOTS
from .cookies import BOTS as COOKIES_BOTS
from .headers import BOTS as HEADERS_BOTS
from .leads import BOTS as LEADS_BOTS
from .recon import BOTS as RECON_BOTS
from .takeover import BOTS as DNS_BOTS
from .thirdparty import BOTS as THIRDPARTY_BOTS
from .tls import BOTS as TLS_BOTS

IMPLEMENTED = {"recon": RECON_BOTS, "headers": HEADERS_BOTS, "cookies": COOKIES_BOTS,
               "tls": TLS_BOTS, "content": CONTENT_BOTS, "dns": DNS_BOTS,
               "leads": LEADS_BOTS, "thirdparty": THIRDPARTY_BOTS}

_tasks: dict[int, asyncio.Task] = {}


class RunRefused(Exception):
    pass


def active_run(program_id: int) -> int | None:
    for run_id, task in _tasks.items():
        if not task.done() and getattr(task, "program_id", None) == program_id:
            return run_id
    return None


def start(program: dict, department: str, bot_ids: list[str] | None, options: dict,
          *, transport=None, resolver=None, tls_connector=None) -> int:
    guard = ScopeGuard(program["in_scope"], program["out_of_scope"],
                       program["automation_allowed"])
    if not guard.automation_allowed:
        raise RunRefused("Automated scanning is turned off for this program. "
                         "Turn it on in the program settings only if the policy allows it.")
    if guard.errors:
        raise RunRefused("The scope list has entries that cannot be read. Fix them first.")
    dept = catalog.department(department)
    available = IMPLEMENTED.get(department)
    if dept is None or available is None:
        raise RunRefused(f"The {department} department is not built yet.")
    order = [b["id"] for b in dept["bots"] if b["id"] in available]
    chosen = [b for b in order if bot_ids is None or b in bot_ids]
    if not chosen:
        raise RunRefused("No bots selected.")
    if active_run(program["id"]):
        raise RunRefused("A run is already in progress for this program.")

    run_id = db.create_run(program["id"], department, chosen, options)
    shared = RunShared(
        program=program, guard=guard, run_id=run_id,
        target=TargetClient(program, guard, run_id, transport=transport),
        sources=SourceClient(program["id"], run_id, transport=transport),
        dns=DnsClient(program, guard, run_id, resolver=resolver),
        options=options,
        tls=TlsClient(program, guard, run_id, connector=tls_connector))
    task = asyncio.get_running_loop().create_task(_run(shared, department, chosen, available))
    task.program_id = program["id"]
    _tasks[run_id] = task
    return run_id


async def _run(shared: RunShared, department: str, chosen: list[str], bots: dict) -> None:
    run_id = shared.run_id
    status = "done"
    started_at = db.get_run(run_id)["started_at"]
    db.add_event(run_id, "", f"Run started: {len(chosen)} bots, "
                             f"{shared.program['rate_limit']} requests/second")
    try:
        for bot_id in chosen:
            ctx = BotContext(shared, department, bot_id)
            db.add_event(run_id, bot_id, "Started")
            try:
                await bots[bot_id].run(ctx)
                ctx.flush()
                s = ctx.stats
                retired = 0
                if department != "recon" and not ctx.partial:
                    # A full pass that did not re-find a card means it is gone.
                    # Recon is exempt: what it sees varies with limits and sources.
                    retired = db.retire_unseen(shared.program["id"], bot_id, started_at)
                    s["retired"] = retired
                db.add_event(run_id, bot_id, f"Finished: {s['assets_new']} new inventory items, "
                                             f"{s['findings_new']} new findings, "
                                             f"{s['leads_new']} new leads"
                                             + (f"; {retired} earlier result"
                                                f"{'s' if retired != 1 else ''} no longer seen"
                                                if retired else ""))
            except asyncio.CancelledError:
                ctx.flush()
                raise
            except OutOfScope as exc:  # a bot bug: it asked for something out of scope
                ctx.flush()
                db.add_event(run_id, bot_id, f"Stopped: tried an out-of-scope target ({exc})",
                             "error")
                status = "failed"
            except Exception as exc:
                ctx.flush()
                db.add_event(run_id, bot_id, f"Crashed: {type(exc).__name__}: {exc}", "error")
                traceback.print_exc()
                status = "failed"
    except asyncio.CancelledError:
        status = "stopped"
        db.add_event(run_id, "", "Stopped by you", "warn")
    finally:
        await shared.close()
        db.finish_run(run_id, status, shared.counts)
        if status != "stopped":
            db.add_event(run_id, "", f"Run {status}")


def stop(run_id: int) -> bool:
    task = _tasks.get(run_id)
    if task and not task.done():
        task.cancel()
        return True
    return False


async def wait(run_id: int) -> None:
    """For tests."""
    task = _tasks.get(run_id)
    if task:
        await asyncio.gather(task, return_exceptions=True)
