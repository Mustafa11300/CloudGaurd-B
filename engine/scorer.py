"""
RISK SCORE CALCULATOR
======================
Takes all findings and computes:
1. Overall Security Posture Score (0-100, higher = safer)
2. Cost Health Score (0-100, higher = less waste)
3. Per-resource risk contribution

REAL-WORLD ANALOGY: Like a credit score — a single number that
summarizes complex underlying data into something actionable.

🔦 LOGIC FOCUS: The scoring formula weights are business decisions.
We chose these weights based on real-world impact data:
- CRITICAL findings get -20 because they represent immediate breach risk
- HIGH gets -10 because they represent significant exploitable vulnerabilities  
- MEDIUM gets -5 for compliance and best practice gaps
- LOW gets -2 for hygiene issues
"""


def calculate_security_score(findings: dict) -> dict:
    """
    Calculates a 0-100 security posture score.

    🔦 LOGIC: Start at 100, subtract for each finding.
    We use a WEIGHTED PENALTY system rather than a simple count
    because 1 CRITICAL finding is worse than 10 LOW findings.

    Formula:
    score = max(0, 100 - (critical*20) - (high*10) - (medium*5) - (low*2))

    WHY THIS FORMULA?
    - Reflects real-world risk weighting used by frameworks like CVSS
    - Ensures CRITICAL issues have outsized impact on the score
    - Score of 0 = catastrophically insecure (many critical issues)
    - Score of 100 = perfectly clean (no findings)
    - Score of 70+ = acceptable for most organizations
    - Score below 50 = urgent remediation needed
    """
    by_severity = findings.get("by_severity", {})

    n_critical = len(by_severity.get("CRITICAL", []))
    n_high = len(by_severity.get("HIGH", []))
    n_medium = len(by_severity.get("MEDIUM", []))
    n_low = len(by_severity.get("LOW", []))

    # Penalty calculation — each severity level costs points
    critical_penalty = n_critical * 20
    high_penalty = n_high * 10
    medium_penalty = n_medium * 5
    low_penalty = n_low * 2

    total_penalty = critical_penalty + high_penalty + medium_penalty + low_penalty

    # Floor at 0 (can't go negative)
    raw_score = max(0, 100 - total_penalty)

    # Determine risk tier for color-coding and messaging
    if raw_score >= 80:
        tier = "GOOD"
        color = "green"
        message = "Security posture is healthy. Continue monitoring."
    elif raw_score >= 60:
        tier = "FAIR"
        color = "yellow"
        message = "Notable issues present. Schedule remediation within 30 days."
    elif raw_score >= 40:
        tier = "POOR"
        color = "orange"
        message = "Significant vulnerabilities detected. Prioritize remediation."
    else:
        tier = "CRITICAL"
        color = "red"
        message = "Immediate action required. Critical exposures detected."

    return {
        "security_score": raw_score,
        "tier": tier,
        "color": color,
        "message": message,
        "breakdown": {
            "critical_count": n_critical,
            "critical_penalty": critical_penalty,
            "high_count": n_high,
            "high_penalty": high_penalty,
            "medium_count": n_medium,
            "medium_penalty": medium_penalty,
            "low_count": n_low,
            "low_penalty": low_penalty,
            "total_penalty": total_penalty
        }
    }


def calculate_cost_waste(resources: list) -> dict:
    """
    Calculates total estimated monthly cloud waste.

    🔦 LOGIC: We identify waste in two categories:
    1. IDLE RESOURCES: Running but not used (EC2 with <5% CPU)
    2. RIGHT-SIZING: Resources much larger than needed

    For idle EC2: waste = monthly_cost * 0.85
    (We assume 85% of cost is waste — keeping 15% buffer for occasional use)
    """
    total_monthly_spend = 0
    total_waste = 0
    waste_items = []

    for resource in resources:
        if resource.get("resource_type") == "EC2":
            monthly = resource.get("monthly_cost_usd", 0)
            cpu = resource.get("cpu_avg_percent", 100)
            hours = resource.get("running_hours_30d", 0)

            total_monthly_spend += monthly

            # Idle instance detection
            if cpu < 5.0 and hours > 168:
                waste = round(monthly * 0.85, 2)
                total_waste += waste
                waste_items.append({
                    "resource_id": resource["resource_id"],
                    "resource_type": "EC2",
                    "monthly_cost": monthly,
                    "estimated_waste": waste,
                    "reason": f"CPU avg {cpu}% over {hours} hours",
                    "recommendation": "Downsize or terminate"
                })

    # Cost health score: what % of spend is NOT wasted?
    if total_monthly_spend > 0:
        waste_percentage = (total_waste / total_monthly_spend) * 100
        cost_health_score = max(0, round(100 - waste_percentage, 1))
    else:
        waste_percentage = 0
        cost_health_score = 100

    return {
        "cost_health_score": cost_health_score,
        "total_monthly_spend_usd": round(total_monthly_spend, 2),
        "total_monthly_waste_usd": round(total_waste, 2),
        "annual_waste_usd": round(total_waste * 12, 2),
        "waste_percentage": round(waste_percentage, 1),
        "waste_items": waste_items,
        "waste_item_count": len(waste_items)
    }


def generate_posture_report(resources: list, findings: dict) -> dict:
    """
    Master report: combines security score + cost analysis
    into a single "posture report" that the dashboard displays.
    """
    security = calculate_security_score(findings)
    cost = calculate_cost_waste(resources)

    return {
        "generated_at": __import__('datetime').datetime.now().isoformat(),
        "resource_count": len(resources),
        "finding_count": findings.get("total_findings", 0),
        "security": security,
        "cost": cost,
        # Top 5 most critical findings for the "fix first" list
        "top_critical_findings": findings.get("by_severity", {}).get("CRITICAL", [])[:5]
    }


if __name__ == "__main__":
    import sys, json , os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from data.generator import generate_full_dataset
    from engine.rules import scan_all_resources

    resources = generate_full_dataset()
    findings = scan_all_resources(resources)
    report = generate_posture_report(resources, findings)

    print("\n📊 POSTURE REPORT:")
    print(f"Security Score: {report['security']['security_score']}/100 ({report['security']['tier']})")
    print(f"Cost Health:    {report['cost']['cost_health_score']}/100")
    print(f"Monthly Waste:  ${report['cost']['total_monthly_waste_usd']}")
    print(f"Annual Waste:   ${report['cost']['annual_waste_usd']}")