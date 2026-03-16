from data.generator import generate_full_dataset
from engine.rules import scan_all_resources
from engine.scorer import generate_posture_report
from elastic.indexer import create_indices, index_resources, index_findings, index_scan_snapshot

print("🚀 Bootstrapping CloudGuard...")
print("=" * 50)

print("\n1️⃣  Creating Elasticsearch indices...")
create_indices()

print("\n2️⃣  Generating simulated cloud dataset...")
resources = generate_full_dataset()

print("\n3️⃣  Running security rule engine...")
findings_result = scan_all_resources(resources)

print("\n4️⃣  Indexing resources...")
index_resources(resources)

print("\n5️⃣  Indexing findings...")
index_findings(findings_result["all_findings"])

print("\n6️⃣  Saving scan snapshot...")
report = generate_posture_report(resources, findings_result)
index_scan_snapshot(report)

print("\n" + "=" * 50)
print("✅ Bootstrap complete!")
print(f"   Security Score:  {report['security']['security_score']}/100")
print(f"   Total Findings:  {report['finding_count']}")
print(f"   Monthly Waste:   ${report['cost']['total_monthly_waste_usd']}")
print("\n🎯 Run the API server: uvicorn main:app --reload")
print("🎯 Run the frontend:   npm run dev (in /glow-app-architect)")