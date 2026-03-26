"""
SCORE API
Endpoints that return the overall security posture score.
"""
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException
from elastic.queries import get_risk_trend
from elastic.client import es
from engine.rules import scan_all_resources
from engine.scorer import generate_posture_report
from elastic.indexer import index_findings, index_scan_snapshot

router = APIRouter()
logger = logging.getLogger(__name__)

_executor = ThreadPoolExecutor(max_workers=4)


def _empty_score_response(message: str = "No scan data available") -> dict:
    return {
        "security_score":    0,
        "cost_health_score": 0,
        "monthly_waste_usd": 0,
        "total_findings":    0,
        "critical_count":    0,
        "high_count":        0,
        "last_scan":         message,
    }


@router.get("/")
def get_score():
    try:
        result = es.search(
            index="scan-history",
            body={"sort": [{"timestamp": "desc"}], "size": 1}
        )
    except Exception as e:
        logger.error(f"Elasticsearch query failed in get_score: {e}")
        raise HTTPException(status_code=503, detail="Database unavailable")

    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        return _empty_score_response("No scans yet — run bootstrap.py first")

    latest = hits[0]["_source"]
    return {
        "security_score":    latest.get("security_score", 0),
        "cost_health_score": latest.get("cost_health_score", 0),
        "monthly_waste_usd": latest.get("monthly_waste_usd", 0),
        "total_findings":    latest.get("total_findings", 0),
        "critical_count":    latest.get("critical_count", 0),
        "high_count":        latest.get("high_count", 0),
        "last_scan":         latest.get("timestamp", "N/A"),
    }


@router.get("/trend")
def get_trend(days: int = 7):
    if days < 1 or days > 90:
        raise HTTPException(status_code=400, detail="days must be between 1 and 90")
    return get_risk_trend(days)


def _fetch_resources() -> list:
    """Fetch all cloud resources from ES."""
    result = es.search(
        index="cloud-resources",
        body={"query": {"match_all": {}}, "size": 500}
    )
    return [h["_source"] for h in result["hits"]["hits"]]


def _delete_old_findings(scan_started_at: str):
    """
    Delete findings from BEFORE this scan started.
    Uses the scan start timestamp — not 'now-1m' — so fresh findings are never touched.
    """
    es.delete_by_query(
        index="security-findings",
        body={"query": {"range": {"detected_at": {"lt": scan_started_at}}}},
        wait_for_completion=False   # fire-and-forget, don't block response
    )


@router.post("/scan")
async def run_scan():
    """
    Fast scan pipeline:
    1. Fetch resources from ES
    2. Run rule engine (CPU-bound, offloaded to thread pool)
    3. Generate posture report (in-memory, instant)
    4. Write new findings + snapshot IN PARALLEL
    5. Delete old findings async (non-blocking)
    """
    from datetime import datetime, timezone
    loop = asyncio.get_event_loop()

    logger.info("Fast scan triggered")
    scan_started_at = datetime.now(timezone.utc).isoformat()

    # Step 1: Fetch resources
    try:
        resources = await loop.run_in_executor(_executor, _fetch_resources)
    except Exception as e:
        logger.error(f"Failed to fetch resources: {e}")
        raise HTTPException(status_code=503, detail=f"Could not load resources: {str(e)}")

    if not resources:
        raise HTTPException(status_code=404, detail="No resources found. Run bootstrap.py first.")

    logger.info(f"Loaded {len(resources)} resources")

    # Step 2: Run rule engine (offload CPU work off the async event loop)
    try:
        findings_result = await loop.run_in_executor(
            _executor,
            scan_all_resources,
            resources
        )
    except Exception as e:
        logger.error(f"Rule engine failed: {e}")
        raise HTTPException(status_code=500, detail=f"Rule engine error: {str(e)}")

    # Step 3: Generate report IN MEMORY — no ES call, instant
    # Do this BEFORE any ES writes so score is based on clean in-memory data
    try:
        report = generate_posture_report(resources, findings_result)
        report["timestamp"] = scan_started_at
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

    # Step 4: Write new findings + snapshot IN PARALLEL
    async def write_findings():
        await loop.run_in_executor(_executor, index_findings, findings_result["all_findings"])

    async def write_snapshot():
        await loop.run_in_executor(_executor, index_scan_snapshot, report)

    try:
        await asyncio.gather(write_findings(), write_snapshot())
    except Exception as e:
        logger.error(f"Write failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to persist scan results: {str(e)}")

    # Step 5: Delete old findings async — doesn't block the response
    # Uses scan_started_at so we NEVER accidentally delete findings we just wrote
    loop.run_in_executor(
        _executor,
        _delete_old_findings,
        scan_started_at
    )

    logger.info(
        f"Scan complete — score: {report['security']['security_score']}, "
        f"findings: {report['finding_count']}, "
        f"waste: ${report['cost']['total_monthly_waste_usd']}"
    )

    return {
        "status":            "success",
        "message":           "Scan completed",
        "security_score":    report["security"]["security_score"],
        "total_findings":    report["finding_count"],
        "monthly_waste_usd": report["cost"]["total_monthly_waste_usd"],
        "scanned_at":        report["generated_at"],
    }
