from elastic.client import es
from elasticsearch.helpers import bulk
from datetime import datetime
import json


def create_indices():
    if not es.indices.exists(index="cloud-resources"):
        es.indices.create(index="cloud-resources", body={
            "mappings": {
                "properties": {
                    "resource_id":    {"type": "keyword"},
                    "resource_type":  {"type": "keyword"},
                    "region":         {"type": "keyword"},
                    "scan_timestamp": {"type": "date"},
                    "config":         {"type": "object", "dynamic": True}
                }
            }
        })
        print("✅ Created index: cloud-resources")

    if not es.indices.exists(index="security-findings"):
        es.indices.create(index="security-findings", body={
            "mappings": {
                "properties": {
                    "finding_id":      {"type": "keyword"},
                    "resource_id":     {"type": "keyword"},
                    "resource_type":   {"type": "keyword"},
                    "rule_id":         {"type": "keyword"},
                    "severity":        {"type": "keyword"},
                    "risk_score":      {"type": "integer"},
                    "title":           {"type": "text"},
                    "description":     {"type": "text"},
                    "remediation":     {"type": "text"},
                    "business_impact": {"type": "text"},
                    "detected_at":     {"type": "date"}
                }
            }
        })
        print("✅ Created index: security-findings")

    if not es.indices.exists(index="scan-history"):
        es.indices.create(index="scan-history", body={
            "mappings": {
                "properties": {
                    "scan_id":           {"type": "keyword"},
                    "timestamp":         {"type": "date"},
                    "security_score":    {"type": "integer"},
                    "cost_health_score": {"type": "integer"},
                    "total_findings":    {"type": "integer"},
                    "critical_count":    {"type": "integer"},
                    "high_count":        {"type": "integer"},
                    "monthly_waste_usd": {"type": "float"}
                }
            }
        })
        print("✅ Created index: scan-history")


def index_resources(resources: list):
    """Bulk index all cloud resources — single HTTP request."""
    print(f"📤 Bulk indexing {len(resources)} resources...")

    actions = [
        {
            "_index": "cloud-resources",
            "_id":    resource["resource_id"],
            "_source": resource
        }
        for resource in resources
    ]

    success, errors = bulk(es, actions, chunk_size=500, raise_on_error=False)
    es.indices.refresh(index="cloud-resources")

    if errors:
        print(f"⚠️  {len(errors)} resources failed to index")
    print(f"✅ Indexed {success} resources")


def index_findings(findings_list: list):
    """Bulk index all findings — single HTTP request instead of 233 individual ones."""
    print(f"📤 Bulk indexing {len(findings_list)} findings...")

    actions = [
        {
            "_index": "security-findings",
            "_id":    finding["finding_id"],
            "_source": finding
        }
        for finding in findings_list
    ]

    success, errors = bulk(es, actions, chunk_size=500, raise_on_error=False)
    es.indices.refresh(index="security-findings")

    if errors:
        print(f"⚠️  {len(errors)} findings failed to index")
    print(f"✅ Indexed {success} findings")


def index_scan_snapshot(report: dict):
    """Save a scan snapshot for trend tracking."""
    import uuid
    snapshot = {
        "scan_id":           str(uuid.uuid4()),
        "timestamp": report.get("timestamp"),
        "security_score":    report["security"]["security_score"],
        "cost_health_score": report["cost"]["cost_health_score"],
        "total_findings":    report["finding_count"],
        "critical_count":    report["security"]["breakdown"]["critical_count"],
        "high_count":        report["security"]["breakdown"]["high_count"],
        "monthly_waste_usd": report["cost"]["total_monthly_waste_usd"]
    }

    es.index(index="scan-history", body=snapshot)
    es.indices.refresh(index="scan-history")
    print("✅ Scan snapshot saved for trend tracking!")