"""
FINDINGS API
Endpoints that return security findings from Elasticsearch.
"""
from fastapi import APIRouter
from elastic.queries import get_findings_by_severity, get_findings_by_resource_type, get_top_risky_resources

router = APIRouter()

@router.get("/summary")
def get_findings_summary():
    """Returns count of findings grouped by severity — used by the donut chart."""
    critical = get_findings_by_severity("CRITICAL")
    high     = get_findings_by_severity("HIGH")
    medium   = get_findings_by_severity("MEDIUM")
    low      = get_findings_by_severity("LOW")

    return {
        "critical": len(critical),
        "high":     len(high),
        "medium":   len(medium),
        "low":      len(low),
        "total":    len(critical) + len(high) + len(medium) + len(low),
        # Chart-ready format for Recharts donut
        "chart_data": [
            {"name": "Critical", "value": len(critical), "color": "#ef4444"},
            {"name": "High",     "value": len(high),     "color": "#f97316"},
            {"name": "Medium",   "value": len(medium),   "color": "#eab308"},
            {"name": "Low",      "value": len(low),      "color": "#22c55e"},
        ]
    }

@router.get("/critical")
def get_critical():
    """Returns all CRITICAL findings with full details."""
    return get_findings_by_severity("CRITICAL")

@router.get("/top")
def get_top(limit: int = 10):
    """Returns top N highest risk findings."""
    return get_top_risky_resources(limit)

@router.get("/by-type")
def by_resource_type():
    """Returns finding counts grouped by resource type (EC2, S3, IAM, etc.)"""
    return get_findings_by_resource_type()