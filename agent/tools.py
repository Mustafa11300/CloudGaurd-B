"""
AGENT TOOLS
============
These are the "hands" of the AI agent.
The agent (Nova 2 Lite) can THINK, but to GET DATA it must call these tools.

REAL-WORLD ANALOGY: Like a detective who can reason and deduce (the AI),
but needs to call the forensics lab (tools) to get actual evidence.

Each tool is a Python function that queries Elasticsearch and returns
structured data the agent can reason over.
"""

from elastic.queries import (
    get_findings_by_severity,
    get_cost_waste_summary,
    get_risk_trend,
    get_top_risky_resources,
    get_findings_by_resource_type
)


def tool_get_critical_findings() -> str:
    """Tool: Fetch all CRITICAL severity findings."""
    findings = get_findings_by_severity("CRITICAL")
    if not findings:
        return "No CRITICAL findings detected. Security posture is healthy."

    summary = f"Found {len(findings)} CRITICAL findings:\n\n"
    for f in findings[:5]:  # Top 5 to avoid token overflow
        summary += f"- {f['title']}\n"
        summary += f"  Resource: {f['resource_id']} ({f['resource_type']})\n"
        summary += f"  Risk Score: {f['risk_score']}/100\n"
        summary += f"  Business Impact: {f['business_impact'][:150]}...\n\n"
    return summary


def tool_get_high_findings() -> str:
    """Tool: Fetch all HIGH severity findings."""
    findings = get_findings_by_severity("HIGH")
    summary = f"Found {len(findings)} HIGH severity findings:\n\n"
    for f in findings[:5]:
        summary += f"- {f['title']} (Risk: {f['risk_score']}/100)\n"
        summary += f"  Fix: {f['remediation'][:100]}...\n\n"
    return summary


def tool_get_cost_waste() -> str:
    """Tool: Get cost waste analysis."""
    data = get_cost_waste_summary()
    findings = data.get("waste_findings", [])

    if not findings:
        return "No significant cost waste detected."

    total_waste = sum(
        float(f.get("description", "").split("$")[2].split("/")[0])
        for f in findings
        if "$" in f.get("description", "")
    ) if findings else 0

    return (
        f"Detected {len(findings)} underutilized resources.\n"
        f"Review the cost findings for specific amounts and recommendations."
    )


def tool_get_risk_trend() -> str:
    """Tool: Get security score trend over time."""
    trend = get_risk_trend(days=7)

    if len(trend) < 2:
        return "Insufficient historical data for trend analysis. Need at least 2 scans."

    first_score = trend[0].get("security_score", 0)
    last_score = trend[-1].get("security_score", 0)
    change = last_score - first_score
    direction = "improved" if change > 0 else "declined" if change < 0 else "unchanged"

    return (
        f"Security trend over last 7 days: Score {direction} by {abs(change)} points.\n"
        f"Started at {first_score}/100, currently at {last_score}/100.\n"
        f"Total data points: {len(trend)} scans."
    )


def tool_get_top_risks() -> str:
    """Tool: Get the top 5 highest-risk resources."""
    resources = get_top_risky_resources(limit=5)
    summary = f"Top {len(resources)} highest risk resources:\n\n"
    for r in resources:
        summary += f"- [{r['severity']}] {r['title']}\n"
        summary += f"  Resource: {r['resource_id']}\n"
        summary += f"  Immediate action: {r['remediation'][:120]}...\n\n"
    return summary


def tool_get_resource_type_breakdown() -> str:
    """Tool: Which resource type has the most problems?"""
    buckets = get_findings_by_resource_type()
    summary = "Findings breakdown by resource type:\n"
    for bucket in buckets:
        summary += f"- {bucket['key']}: {bucket['doc_count']} total findings\n"
    return summary


# Registry: maps tool names to functions
# The agent uses this registry to know what tools are available
TOOL_REGISTRY = {
    "get_critical_findings": tool_get_critical_findings,
    "get_high_findings": tool_get_high_findings,
    "get_cost_waste": tool_get_cost_waste,
    "get_risk_trend": tool_get_risk_trend,
    "get_top_risks": tool_get_top_risks,
    "get_resource_type_breakdown": tool_get_resource_type_breakdown,
}