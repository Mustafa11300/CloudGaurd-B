"""
ES|QL QUERY LIBRARY
====================
Named queries that answer specific business questions.

🔦 LOGIC FOCUS: Each query answers a BUSINESS QUESTION, not just "get data".
Label every query with the question it answers.

These queries are what the AI agent calls when it needs data to reason over.
"""

from elastic.client import es


def get_findings_by_severity(severity: str = None) -> list:
    """
    Q: What security problems exist, grouped by how bad they are?
    """
    query = {"match_all": {}} if not severity else {"term": {"severity": severity}}

    result = es.search(
        index="security-findings",
        body={
            "query": query,
            "sort": [{"risk_score": "desc"}],
            "size": 100
        }
    )

    return [hit["_source"] for hit in result["hits"]["hits"]]


def get_cost_waste_summary() -> dict:
    """
    Q: How much money are we wasting and on what?
    Uses ES aggregations — like GROUP BY in SQL.
    """
    result = es.search(
        index="security-findings",
        body={
            "query": {"term": {"rule_id": "EC2-001"}},
            "size": 100
        }
    )
    findings = [hit["_source"] for hit in result["hits"]["hits"]]
    return {"waste_findings": findings, "count": len(findings)}


def get_risk_trend(days: int = 7) -> list:
    """
    Q: Is our security posture getting better or worse over time?
    """
    from datetime import datetime, timedelta
    since = (datetime.now() - timedelta(days=days)).isoformat()

    result = es.search(
        index="scan-history",
        body={
            "query": {"range": {"timestamp": {"gte": since}}},
            "sort": [{"timestamp": "asc"}],
            "size": 50
        }
    )

    return [hit["_source"] for hit in result["hits"]["hits"]]


def get_top_risky_resources(limit: int = 10) -> list:
    """
    Q: Which specific resources need attention most urgently?
    """
    result = es.search(
        index="security-findings",
        body={
            "query": {"terms": {"severity": ["CRITICAL", "HIGH"]}},
            "sort": [{"risk_score": "desc"}],
            "size": limit
        }
    )
    return [hit["_source"] for hit in result["hits"]["hits"]]


def get_findings_by_resource_type() -> dict:
    """
    Q: Which type of cloud resource has the most problems?
    Uses ES aggregations for grouping.
    """
    result = es.search(
        index="security-findings",
        body={
            "size": 0,  # Don't return documents, just aggregation
            "aggs": {
                "by_type": {
                    "terms": {"field": "resource_type"},
                    "aggs": {
                        "by_severity": {"terms": {"field": "severity"}}
                    }
                }
            }
        }
    )
    return result["aggregations"]["by_type"]["buckets"]