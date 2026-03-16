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

@router.get("/cost-waste")
def get_cost_waste():
    import re
    from elastic.client import es

    # Query ES directly for EC2-001 rule specifically — bypasses size limits
    result = es.search(
        index="security-findings",
        body={
            "query": {"term": {"rule_id": "EC2-001"}},
            "size": 500,
            "sort": [{"risk_score": "desc"}]
        }
    )

    findings = [h["_source"] for h in result["hits"]["hits"]]
    print(f"EC2-001 findings found: {len(findings)}")

    cost_items = []
    total_waste = 0
    total_cost  = 0

    for f in findings:
        desc = f.get("description", "")
        print(f"Parsing: {desc[:80]}")

        cpu_match   = re.search(r"([\d.]+)% average CPU", desc)
        hours_match = re.search(r"over ([\d]+) running hours", desc)
        cost_match  = re.search(r"Monthly cost: \$([\d]+\.[\d]+)", desc)
        waste_match = re.search(r"Estimated waste: \$([\d]+\.[\d]+)", desc)

        monthly_cost    = float(cost_match.group(1))  if cost_match  else 0
        estimated_waste = float(waste_match.group(1)) if waste_match else 0
        cpu_avg         = float(cpu_match.group(1))   if cpu_match   else 0
        running_hours   = int(hours_match.group(1))   if hours_match else 0

        if monthly_cost == 0:
            continue

        total_waste += estimated_waste
        total_cost  += monthly_cost

        cost_items.append({
            "resource_id":     f.get("resource_id"),
            "resource_type":   "EC2",
            "instance_type":   f.get("resource_type", "EC2"),
            "region":          "us-east-1",
            "cpu_avg":         cpu_avg,
            "running_hours":   running_hours,
            "monthly_cost":    round(monthly_cost, 2),
            "estimated_waste": round(estimated_waste, 2),
            "remediation":     f.get("remediation", ""),
        })

    savings_rate = round((total_waste / total_cost * 100)) if total_cost > 0 else 0

    return {
        "items":        cost_items,
        "total_waste":  round(total_waste, 2),
        "annual_waste": round(total_waste * 12, 2),
        "idle_count":   len(cost_items),
        "savings_rate": savings_rate,
        "total_cost":   round(total_cost, 2),
    }