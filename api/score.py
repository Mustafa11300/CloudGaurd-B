"""
SCORE API
Endpoints that return the overall security posture score.
"""
from fastapi import APIRouter
from elastic.queries import get_findings_by_severity, get_risk_trend
from elastic.client import es

router = APIRouter()

@router.get("/")
def get_score():
    """
    Returns the current security posture score + cost health score.
    This is what the big ScoreCard components on the dashboard display.
    """
    # Get latest scan snapshot from Elasticsearch
    try:
        result = es.search(
            index="scan-history",
            body={
                "sort": [{"timestamp": "desc"}],
                "size": 1
            }
        )
        if result["hits"]["hits"]:
            latest = result["hits"]["hits"][0]["_source"]
            return {
                "security_score":    latest.get("security_score", 0),
                "cost_health_score": latest.get("cost_health_score", 0),
                "monthly_waste":     latest.get("monthly_waste_usd", 0),
                "total_findings":    latest.get("total_findings", 0),
                "critical_count":    latest.get("critical_count", 0),
                "high_count":        latest.get("high_count", 0),
                "last_scan":         latest.get("timestamp", "N/A")
            }
    except Exception as e:
        print(f"Score fetch error: {e}")

    return {
        "security_score": 0,
        "cost_health_score": 0,
        "monthly_waste": 0,
        "total_findings": 0,
        "critical_count": 0,
        "high_count": 0,
        "last_scan": "No scans yet — run bootstrap.py first"
    }

@router.get("/trend")
def get_trend(days: int = 7):
    """Returns score history for the drift/trend line chart."""
    return get_risk_trend(days)