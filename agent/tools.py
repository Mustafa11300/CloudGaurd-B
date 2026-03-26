"""
CLOUDGUARD AGENT TOOLS — Hackathon Edition
==========================================
Elite tool implementations with:
- Structured scoring + compliance framework mapping
- Cost impact quantification
- Remediation complexity ratings
- Rich context for LLM synthesis

Each tool returns maximally useful data so Nova can produce
detailed, actionable, impressive audit reports.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from elastic.queries import (
    get_findings_by_severity,
    get_cost_waste_summary,
    get_risk_trend,
    get_top_risky_resources,
    get_findings_by_resource_type,
)

logger = logging.getLogger(__name__)

# ─── Compliance Framework Mappings ───────────────────────────────────────────

CIS_MAPPING = {
    "S3 Bucket Publicly Accessible":        "CIS AWS 2.1.5",
    "S3 Bucket No Encryption":              "CIS AWS 2.1.1",
    "Root Account MFA Disabled":            "CIS AWS 1.5",
    "IAM Password Policy Weak":             "CIS AWS 1.9",
    "CloudTrail Not Enabled":               "CIS AWS 3.1",
    "VPC Flow Logs Disabled":               "CIS AWS 3.9",
    "Security Group Open to World":         "CIS AWS 5.2",
    "RDS Publicly Accessible":              "CIS AWS 2.3.2",
    "EBS Snapshot Public":                  "CIS AWS 2.2.1",
    "KMS Key Rotation Disabled":            "CIS AWS 3.7",
}

NIST_MAPPING = {
    "S3 Bucket Publicly Accessible":        "NIST AC-3, AC-17",
    "Root Account MFA Disabled":            "NIST IA-2, IA-5",
    "CloudTrail Not Enabled":               "NIST AU-2, AU-12",
    "Security Group Open to World":         "NIST SC-7",
    "IAM Password Policy Weak":             "NIST IA-5",
    "RDS Publicly Accessible":              "NIST AC-3, SC-7",
    "KMS Key Rotation Disabled":            "NIST SC-12, SC-28",
}

REMEDIATION_COMPLEXITY = {
    "Enable 'Block Public Access'":  "LOW  (< 5 min, zero downtime)",
    "Enable MFA":                    "LOW  (< 15 min)",
    "Enable CloudTrail":             "LOW  (< 10 min)",
    "Enable encryption":             "MED  (may require reboot/migration)",
    "Update Security Group":         "LOW  (< 5 min, verify app connectivity)",
    "Rotate KMS Key":                "MED  (coordinate with dependent services)",
    "Update IAM Policy":             "MED  (test in staging first)",
    "Restrict RDS access":           "MED  (verify connection strings)",
}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _compliance_tags(title: str) -> str:
    cis  = CIS_MAPPING.get(title, "CIS: Review Required")
    nist = NIST_MAPPING.get(title, "NIST: Review Required")
    return f"{cis} | {nist}"


def _remediation_effort(remediation_text: str) -> str:
    for keyword, complexity in REMEDIATION_COMPLEXITY.items():
        if keyword.lower() in remediation_text.lower():
            return complexity
    return "MED  (estimate 30–60 min)"


def _exploit_likelihood(risk_score: int) -> str:
    if risk_score >= 90:
        return "CRITICAL — Active exploitation possible within 24h"
    if risk_score >= 75:
        return "HIGH — Commonly targeted attack vector"
    if risk_score >= 50:
        return "MEDIUM — Exploitable with moderate effort"
    return "LOW — Requires targeted effort"


def _safe_get(obj: Any, key: str, default: str = "N/A") -> Any:
    return obj.get(key, default) if isinstance(obj, dict) else default


# ─── Tools ────────────────────────────────────────────────────────────────────

def tool_get_critical_findings() -> str:
    """
    Fetch CRITICAL severity findings with full audit context.
    Returns compliance mappings, exploit likelihood, and effort estimates.
    """
    try:
        findings = get_findings_by_severity("CRITICAL")
    except Exception as e:
        logger.error(f"Elasticsearch query failed (critical): {e}")
        return f"ERROR: Could not retrieve CRITICAL findings — {e}"

    if not findings:
        return (
            "✅ No CRITICAL findings detected.\n"
            "Security posture is healthy at this severity tier.\n"
            "Continue monitoring for emerging threats."
        )

    lines = [
        f"🔴 CRITICAL FINDINGS — {len(findings)} issue(s) detected",
        f"   Scan timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "=" * 60,
    ]

    for i, f in enumerate(findings[:7], 1):          # Up to 7 to give Nova more signal
        title       = _safe_get(f, "title")
        resource_id = _safe_get(f, "resource_id")
        res_type    = _safe_get(f, "resource_type")
        risk_score  = _safe_get(f, "risk_score", 0)
        remediation = _safe_get(f, "remediation", "See AWS documentation")
        impact      = _safe_get(f, "business_impact", "Data exposure risk")
        region      = _safe_get(f, "region", "us-east-1")

        lines += [
            f"\n[{i}] {title}",
            f"    Resource  : {resource_id} ({res_type}) — {region}",
            f"    Risk Score: {risk_score}/100 | {_exploit_likelihood(risk_score)}",
            f"    Compliance: {_compliance_tags(title)}",
            f"    Impact    : {impact[:200]}",
            f"    Fix       : {remediation[:200]}",
            f"    Effort    : {_remediation_effort(remediation)}",
        ]

    lines += [
        "\n" + "=" * 60,
        f"Total CRITICAL exposure: {len(findings)} misconfigured resources.",
        "Prioritize by risk score. All CRITICAL items require same-day remediation.",
    ]
    return "\n".join(lines)


def tool_get_high_findings() -> str:
    """
    Fetch HIGH severity findings with remediation guidance and compliance mapping.
    """
    try:
        findings = get_findings_by_severity("HIGH")
    except Exception as e:
        logger.error(f"Elasticsearch query failed (high): {e}")
        return f"ERROR: Could not retrieve HIGH findings — {e}"

    if not findings:
        return "✅ No HIGH severity findings. Good compliance posture at this tier."

    lines = [
        f"🟠 HIGH SEVERITY FINDINGS — {len(findings)} issue(s) detected",
        "=" * 60,
    ]

    for i, f in enumerate(findings[:7], 1):
        title       = _safe_get(f, "title")
        resource_id = _safe_get(f, "resource_id")
        res_type    = _safe_get(f, "resource_type")
        risk_score  = _safe_get(f, "risk_score", 0)
        remediation = _safe_get(f, "remediation", "See AWS documentation")
        region      = _safe_get(f, "region", "us-east-1")

        lines += [
            f"\n[{i}] {title}",
            f"    Resource  : {resource_id} ({res_type}) — {region}",
            f"    Risk Score: {risk_score}/100",
            f"    Compliance: {_compliance_tags(title)}",
            f"    Fix       : {remediation[:200]}",
            f"    Effort    : {_remediation_effort(remediation)}",
        ]

    lines += [
        "\n" + "=" * 60,
        f"Remediate {len(findings)} HIGH findings within 72 hours per SLA best practices.",
    ]
    return "\n".join(lines)


def tool_get_cost_waste() -> str:
    """
    Get cost waste analysis with annualized projections and ROI of remediation.
    """
    try:
        data = get_cost_waste_summary()
    except Exception as e:
        logger.error(f"Cost waste query failed: {e}")
        return f"ERROR: Could not retrieve cost waste data — {e}"

    findings = data.get("waste_findings", [])

    if not findings:
        return (
            "✅ No significant cost waste detected.\n"
            "Resource utilization is within acceptable thresholds.\n"
            "Recommend scheduling quarterly rightsizing reviews."
        )

    # Parse dollar amounts safely
    monthly_waste = 0.0
    parsed = []
    for f in findings:
        desc = _safe_get(f, "description", "")
        parts = desc.split("$")
        amount = 0.0
        if len(parts) >= 3:
            try:
                amount = float(parts[2].split("/")[0].replace(",", "").strip())
            except ValueError:
                pass
        parsed.append({**f, "_parsed_amount": amount})
        monthly_waste += amount

    annual_waste = monthly_waste * 12

    lines = [
        f"💸 COST WASTE ANALYSIS — {len(findings)} underutilized resource(s)",
        f"   Monthly waste : ${monthly_waste:,.2f}",
        f"   Annual waste  : ${annual_waste:,.2f}",
        "=" * 60,
    ]

    # Sort by waste amount descending
    for i, f in enumerate(sorted(parsed, key=lambda x: x["_parsed_amount"], reverse=True)[:8], 1):
        title   = _safe_get(f, "title", "Unnamed resource")
        res_id  = _safe_get(f, "resource_id", "unknown")
        desc    = _safe_get(f, "description", "No description")
        amount  = f["_parsed_amount"]
        action  = _safe_get(f, "recommended_action", "Review and rightsize or terminate")

        lines += [
            f"\n[{i}] {title}",
            f"    Resource  : {res_id}",
            f"    Monthly   : ${amount:,.2f} | Annual: ${amount * 12:,.2f}",
            f"    Detail    : {desc[:180]}",
            f"    Action    : {action[:150]}",
        ]

    lines += [
        "\n" + "=" * 60,
        f"ROI of remediation: Eliminating these resources saves ${annual_waste:,.0f}/year.",
        "Rightsizing alone typically yields 20-30% EC2 cost reduction.",
    ]
    return "\n".join(lines)


def tool_get_risk_trend() -> str:
    """
    Security score trend with velocity analysis and regression detection.
    """
    try:
        trend = get_risk_trend(days=14)    # Extended to 14 days for richer signal
    except Exception as e:
        logger.error(f"Risk trend query failed: {e}")
        return f"ERROR: Could not retrieve risk trend data — {e}"

    if not trend:
        return "No trend data available. First scan may still be processing."

    if len(trend) < 2:
        score = trend[0].get("security_score", 0)
        return (
            f"Only 1 scan available (score: {score}/100).\n"
            f"Trend analysis requires minimum 2 scans. Schedule next scan to establish baseline."
        )

    scores    = [t.get("security_score", 0) for t in trend]
    first     = scores[0]
    last      = scores[-1]
    peak      = max(scores)
    trough    = min(scores)
    change    = last - first
    direction = "📈 IMPROVED" if change > 0 else ("📉 DECLINED" if change < 0 else "➡️ STABLE")

    # Simple velocity: change per day
    days_span = len(trend)
    velocity  = change / max(days_span - 1, 1)

    # Regression detection: any single-day drop > 10 points
    regressions = []
    for i in range(1, len(trend)):
        drop = trend[i].get("security_score", 0) - trend[i - 1].get("security_score", 0)
        if drop <= -10:
            regressions.append((i, trend[i].get("date", f"Day {i}"), drop))

    lines = [
        f"📊 SECURITY SCORE TREND — Last {days_span} days",
        "=" * 60,
        f"   Status    : {direction} by {abs(change):.1f} pts",
        f"   Start     : {first}/100  →  Current: {last}/100",
        f"   Peak      : {peak}/100  |  Trough : {trough}/100",
        f"   Velocity  : {velocity:+.1f} pts/day",
        f"   Datapoints: {days_span} scans",
    ]

    if regressions:
        lines.append(f"\n⚠️  Regression Events Detected ({len(regressions)}):")
        for idx, date, drop in regressions:
            lines.append(f"   - {date}: score dropped {drop:.0f} pts (investigate new deployments)")

    # Projection
    projected_30d = min(100, max(0, last + (velocity * 30)))
    lines += [
        f"\n   30-day projection (at current velocity): {projected_30d:.0f}/100",
        "=" * 60,
    ]

    if last < 60:
        lines.append("🚨 ALERT: Score below 60 — HIGH RISK. Escalate to security team immediately.")
    elif last < 75:
        lines.append("⚠️  Score below 75 — moderate risk. Prioritize this week's remediations.")
    else:
        lines.append("✅ Score above 75 — acceptable posture. Focus on CRITICAL items.")

    return "\n".join(lines)


def tool_get_top_risks() -> str:
    """
    Top highest-risk resources ranked by risk score with attack surface analysis.
    """
    try:
        resources = get_top_risky_resources(limit=8)
    except Exception as e:
        logger.error(f"Top risks query failed: {e}")
        return f"ERROR: Could not retrieve top risk data — {e}"

    if not resources:
        return "✅ No high-risk resources found. Infrastructure is in good shape."

    lines = [
        f"🎯 TOP RISK RESOURCES — {len(resources)} highest-priority targets",
        "   (Ranked by composite risk score)",
        "=" * 60,
    ]

    total_risk = sum(_safe_get(r, "risk_score", 0) for r in resources)

    for i, r in enumerate(resources, 1):
        severity    = _safe_get(r, "severity")
        title       = _safe_get(r, "title")
        resource_id = _safe_get(r, "resource_id")
        risk_score  = _safe_get(r, "risk_score", 0)
        remediation = _safe_get(r, "remediation", "Consult AWS security best practices")
        res_type    = _safe_get(r, "resource_type", "")
        region      = _safe_get(r, "region", "")

        severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(severity, "⚪")

        lines += [
            f"\n[#{i}] {severity_icon} [{severity}] {title}",
            f"     Resource : {resource_id}" + (f"  ({res_type})" if res_type else ""),
            f"     Region   : {region}" if region else "",
            f"     Risk     : {risk_score}/100 — {_exploit_likelihood(risk_score)}",
            f"     Fix      : {remediation[:200]}",
            f"     Effort   : {_remediation_effort(remediation)}",
            f"     Comply   : {_compliance_tags(title)}",
        ]

    lines = [l for l in lines if l]   # drop empty region lines
    lines += [
        "\n" + "=" * 60,
        f"Aggregate risk score: {total_risk} across top {len(resources)} resources.",
        "Fix in rank order for maximum risk reduction per engineer-hour.",
    ]
    return "\n".join(lines)


def tool_get_resource_type_breakdown() -> str:
    """
    Resource type breakdown with risk concentration analysis.
    Shows which service categories are your biggest attack surface.
    """
    try:
        buckets = get_findings_by_resource_type()
    except Exception as e:
        logger.error(f"Resource type breakdown query failed: {e}")
        return f"ERROR: Could not retrieve resource breakdown — {e}"

    if not buckets:
        return "No resource type data available."

    total = sum(b.get("doc_count", 0) for b in buckets)
    lines = [
        f"📋 RESOURCE TYPE BREAKDOWN — {total} total findings across {len(buckets)} service(s)",
        "=" * 60,
    ]

    for b in sorted(buckets, key=lambda x: x.get("doc_count", 0), reverse=True):
        svc   = b.get("key", "Unknown")
        count = b.get("doc_count", 0)
        pct   = (count / total * 100) if total else 0
        bar   = "█" * int(pct / 5)   # Visual bar (each block = 5%)
        lines.append(f"  {svc:<30} {count:>4} findings  {pct:5.1f}%  {bar}")

    top_svc = buckets[0].get("key", "Unknown") if buckets else "N/A"
    lines += [
        "=" * 60,
        f"Highest concentration: {top_svc} — address this service type first.",
        "Focus engineering effort where the attack surface is widest.",
    ]
    return "\n".join(lines)


def tool_get_compliance_scorecard() -> str:
    """
    Synthetic compliance scorecard across CIS + NIST control families.
    Aggregates findings into a board-ready posture summary.
    """
    try:
        critical = get_findings_by_severity("CRITICAL")
        high     = get_findings_by_severity("HIGH")
    except Exception as e:
        return f"ERROR: Could not build compliance scorecard — {e}"

    all_findings = (critical or []) + (high or [])

    # Count by compliance framework
    cis_failures  = {}
    nist_failures = {}

    for f in all_findings:
        title = _safe_get(f, "title")
        cis   = CIS_MAPPING.get(title)
        nist  = NIST_MAPPING.get(title)
        if cis:
            cis_failures[cis] = cis_failures.get(cis, 0) + 1
        if nist:
            nist_failures[nist] = nist_failures.get(nist, 0) + 1

    total_findings    = len(all_findings)
    total_critical    = len(critical or [])
    total_high        = len(high or [])

    # Rough posture score: start at 100, deduct per finding
    posture = max(0, 100 - (total_critical * 10) - (total_high * 4))
    grade   = "A" if posture >= 90 else "B" if posture >= 75 else "C" if posture >= 60 else "D" if posture >= 40 else "F"

    lines = [
        "📊 COMPLIANCE SCORECARD",
        "=" * 60,
        f"   Posture Score : {posture}/100  (Grade: {grade})",
        f"   Critical Gaps : {total_critical}",
        f"   High Gaps     : {total_high}",
        f"   Total Findings: {total_findings}",
        "",
        "CIS AWS Benchmark Failures:",
    ]
    if cis_failures:
        for control, count in sorted(cis_failures.items()):
            lines.append(f"   ✗ {control} — {count} resource(s) non-compliant")
    else:
        lines.append("   ✓ No mapped CIS failures detected")

    lines.append("\nNIST CSF Control Failures:")
    if nist_failures:
        for control, count in sorted(nist_failures.items()):
            lines.append(f"   ✗ {control} — {count} resource(s) non-compliant")
    else:
        lines.append("   ✓ No mapped NIST failures detected")

    lines += [
        "=" * 60,
        f"Board Summary: {'IMMEDIATE ACTION REQUIRED' if grade in 'DF' else 'Requires attention' if grade == 'C' else 'Acceptable — continue hardening'}",
    ]
    return "\n".join(lines)


# ─── Registry ─────────────────────────────────────────────────────────────────

TOOL_REGISTRY = {
    "get_critical_findings":    tool_get_critical_findings,
    "get_high_findings":        tool_get_high_findings,
    "get_cost_waste":           tool_get_cost_waste,
    "get_risk_trend":           tool_get_risk_trend,
    "get_top_risks":            tool_get_top_risks,
    "get_resource_type_breakdown": tool_get_resource_type_breakdown,
    "get_compliance_scorecard": tool_get_compliance_scorecard,
}

TOOL_DESCRIPTIONS = {
    "get_critical_findings":       "CRITICAL severity findings with compliance mapping and exploit likelihood",
    "get_high_findings":           "HIGH severity findings with remediation steps and effort estimates",
    "get_cost_waste":              "Underutilized resources with annualized waste projections",
    "get_risk_trend":              "14-day security score trend with regression detection",
    "get_top_risks":               "Top 8 highest-risk resources ranked by composite score",
    "get_resource_type_breakdown": "Attack surface distribution across AWS service types",
    "get_compliance_scorecard":    "Board-ready CIS + NIST compliance scorecard with posture grade",
}