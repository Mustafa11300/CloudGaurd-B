"""
ELASTICSEARCH INDEXER
======================
This file pushes all our data INTO Elasticsearch.

REAL-WORLD ANALOGY: Like filing a report into a database.
Each resource and finding gets its own "document" (like a row in a database)
stored in an "index" (like a table in a database).

OUR INDICES:
- cloud-resources    → all raw resource configs
- security-findings  → all detected problems
- scan-history       → timestamped scan results for trend tracking
"""

from elastic.client import es
from datetime import datetime
import json


def create_indices():
    """
    Creates the ES index structure if it doesn't exist.
    Like creating database tables before inserting data.
    """

    # Index for raw cloud resources
    if not es.indices.exists(index="cloud-resources"):
        es.indices.create(index="cloud-resources", body={
            "mappings": {
                "properties": {
                    "resource_id": {"type": "keyword"},
                    "resource_type": {"type": "keyword"},
                    "region": {"type": "keyword"},
                    "scan_timestamp": {"type": "date"},
                    # Store full resource as nested object
                    "config": {"type": "object", "dynamic": True}
                }
            }
        })
        print("✅ Created index: cloud-resources")

    # Index for security findings
    if not es.indices.exists(index="security-findings"):
        es.indices.create(index="security-findings", body={
            "mappings": {
                "properties": {
                    "finding_id": {"type": "keyword"},
                    "resource_id": {"type": "keyword"},
                    "resource_type": {"type": "keyword"},
                    "rule_id": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "risk_score": {"type": "integer"},
                    "title": {"type": "text"},
                    "description": {"type": "text"},
                    "remediation": {"type": "text"},
                    "business_impact": {"type": "text"},
                    "detected_at": {"type": "date"}
                }
            }
        })
        print("✅ Created index: security-findings")

    # Index for scan history (enables trend/drift charts)
    if not es.indices.exists(index="scan-history"):
        es.indices.create(index="scan-history", body={
            "mappings": {
                "properties": {
                    "scan_id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "security_score": {"type": "integer"},
                    "cost_health_score": {"type": "integer"},
                    "total_findings": {"type": "integer"},
                    "critical_count": {"type": "integer"},
                    "high_count": {"type": "integer"},
                    "monthly_waste_usd": {"type": "float"}
                }
            }
        })
        print("✅ Created index: scan-history")


def index_resources(resources: list):
    """Bulk inserts all cloud resources into Elasticsearch."""
    print(f"📤 Indexing {len(resources)} resources...")

    for resource in resources:
        es.index(
            index="cloud-resources",
            id=resource["resource_id"],
            body=resource
        )

    es.indices.refresh(index="cloud-resources")
    print("✅ Resources indexed!")


def index_findings(findings_list: list):
    """Bulk inserts all security findings into Elasticsearch."""
    print(f"📤 Indexing {len(findings_list)} findings...")

    for finding in findings_list:
        es.index(
            index="security-findings",
            id=finding["finding_id"],
            body=finding
        )

    es.indices.refresh(index="security-findings")
    print("✅ Findings indexed!")


def index_scan_snapshot(report: dict):
    """Saves a snapshot of scores at a point in time — enables the drift chart."""
    import uuid
    snapshot = {
        "scan_id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "security_score": report["security"]["security_score"],
        "cost_health_score": report["cost"]["cost_health_score"],
        "total_findings": report["finding_count"],
        "critical_count": report["security"]["breakdown"]["critical_count"],
        "high_count": report["security"]["breakdown"]["high_count"],
        "monthly_waste_usd": report["cost"]["total_monthly_waste_usd"]
    }

    es.index(index="scan-history", body=snapshot)
    es.indices.refresh(index="scan-history")
    print("✅ Scan snapshot saved for trend tracking!")