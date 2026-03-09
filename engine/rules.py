"""
MISCONFIGURATION RULE ENGINE
=============================
This is the most important file in the project.

Think of this as a SECURITY CHECKLIST that a cloud security expert would run
through manually — we've encoded their expertise into code.

Each function = one rule.
Each rule returns a "Finding" (a detected problem) or None (no problem).

REAL-WORLD ANALOGY: Like a home inspector who goes room by room with a
checklist. Each item on the checklist is a "rule". If something fails,
they write it up as a "finding" in their report.

SEVERITY LEVELS:
- CRITICAL: Fix immediately. Data exposure or account takeover risk.
- HIGH:     Fix this week. Significant attack surface.
- MEDIUM:   Fix this month. Compliance and best practice violations.
- LOW:      Fix when possible. Minor improvements.
"""

from datetime import datetime
from typing import Optional


def create_finding(resource_id: str, resource_type: str, rule_id: str,
                   title: str, description: str, severity: str,
                   risk_score: int, remediation: str,
                   business_impact: str) -> dict:
    """
    Helper function: creates a standardized finding object.
    Every rule uses this same structure so the dashboard can display them consistently.

    WHY STANDARDIZE? Think of it like a bug report template.
    Every bug report has: title, description, severity, steps to fix.
    Our findings follow the same idea.
    """
    return {
        "finding_id": f"{rule_id}-{resource_id}",
        "resource_id": resource_id,
        "resource_type": resource_type,
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "severity": severity,           # CRITICAL / HIGH / MEDIUM / LOW
        "risk_score": risk_score,       # 0-100, higher = more dangerous
        "remediation": remediation,     # Exact steps to fix
        "business_impact": business_impact,  # WHY this matters in business terms
        "detected_at": datetime.now().isoformat()
    }


# ============================================================
# EC2 RULES
# ============================================================

def check_ec2_underutilized(resource: dict) -> Optional[dict]:
    """
    RULE: Underutilized EC2 Instance (COST WASTE)

    If a server runs at less than 5% CPU for 30 days, it's essentially
    doing nothing but costing money. This is one of the most common and
    expensive cloud mistakes.

    🔦 LOGIC: cpu_avg < 5% AND running_hours > 168 (1 week)
    WHY 5%? Industry standard threshold for "idle" server.
    WHY 168 hours? One week running idle = definitely intentional waste.
    """
    if resource.get("resource_type") != "EC2":
        return None

    cpu = resource.get("cpu_avg_percent", 100)
    hours = resource.get("running_hours_30d", 0)

    if cpu < 5.0 and hours > 168:
        # Calculate estimated waste: if running at 5% CPU, we're paying for 95% of nothing
        monthly_cost = resource.get("monthly_cost_usd", 0)
        estimated_waste = round(monthly_cost * 0.85, 2)  # 85% of cost is wasted

        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="EC2",
            rule_id="EC2-001",
            title="Severely Underutilized EC2 Instance",
            description=(
                f"Instance has only {cpu}% average CPU utilization over "
                f"{hours} running hours. Monthly cost: ${monthly_cost}. "
                f"Estimated waste: ${estimated_waste}/month."
            ),
            severity="MEDIUM",
            risk_score=45,
            remediation=(
                "1. Review workload requirements. "
                "2. Consider downsizing to a smaller instance type. "
                "3. Evaluate if Auto Scaling can replace this fixed instance. "
                "4. If unused, consider stopping or terminating the instance."
            ),
            business_impact=(
                f"Wasting approximately ${estimated_waste}/month (${estimated_waste * 12}/year). "
                "Multiplied across all underutilized instances, this represents significant "
                "unnecessary cloud spend."
            )
        )
    return None


def check_ec2_untagged(resource: dict) -> Optional[dict]:
    """
    RULE: EC2 Instance Missing Purpose Tag (GOVERNANCE)

    Tags are labels on cloud resources that tell you WHO owns it, WHAT it's for,
    and WHICH team is responsible. Without tags, you can't:
    - Allocate costs to the right team
    - Know if you can safely delete it
    - Enforce access policies

    🔦 LOGIC: has_purpose_tag == False
    """
    if resource.get("resource_type") != "EC2":
        return None

    if not resource.get("has_purpose_tag", True):
        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="EC2",
            rule_id="EC2-002",
            title="EC2 Instance Missing Purpose Tag",
            description="Instance has no 'purpose' or 'owner' tag. Cannot determine ownership or business function.",
            severity="LOW",
            risk_score=20,
            remediation=(
                "Add tags: Purpose=<workload-name>, Owner=<team-email>, "
                "Environment=<prod|staging|dev>, CostCenter=<code>"
            ),
            business_impact=(
                "Without tags, cost allocation is impossible. You cannot determine "
                "which team owns this resource or whether it is safe to decommission."
            )
        )
    return None


# ============================================================
# S3 RULES
# ============================================================

def check_s3_public_access(resource: dict) -> Optional[dict]:
    """
    RULE: S3 Bucket Publicly Accessible (CRITICAL)

    This is one of the most common causes of data breaches in the cloud.
    Thousands of companies have accidentally exposed sensitive data via
    public S3 buckets (Capital One breach, 2019 — affected 100M customers).

    🔦 LOGIC: public_access_blocked == False
    WHY CRITICAL? Anyone on the internet can download your files.
    Risk score = 95 (highest possible, just below 100)
    """
    if resource.get("resource_type") != "S3":
        return None

    if not resource.get("public_access_blocked", True):
        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="S3",
            rule_id="S3-001",
            title="S3 Bucket Publicly Accessible",
            description=(
                f"Bucket contains {resource.get('object_count', 'unknown')} objects "
                f"({resource.get('size_gb', 0)} GB) and is accessible to the public internet. "
                "Anyone with the URL can read, list, or potentially write to this bucket."
            ),
            severity="CRITICAL",
            risk_score=95,
            remediation=(
                "IMMEDIATE ACTION REQUIRED: "
                "1. Go to S3 Console → Select bucket → Permissions tab. "
                "2. Click 'Block Public Access' → Enable all 4 settings. "
                "3. Review bucket policy and ACLs for public grants. "
                "4. Audit what data is in the bucket — assume it has been accessed."
            ),
            business_impact=(
                "A publicly accessible S3 bucket can expose customer data, "
                "intellectual property, credentials, and backups. Average cost of a "
                "data breach: $4.45M (IBM, 2023). Regulatory fines possible under GDPR/HIPAA."
            )
        )
    return None


def check_s3_encryption(resource: dict) -> Optional[dict]:
    """
    RULE: S3 Bucket Encryption Disabled (HIGH)

    Encryption means data is scrambled when stored — even if someone gets the
    raw storage, they can't read it without the key.
    All major compliance frameworks (PCI-DSS, HIPAA, SOC2) require encryption at rest.

    🔦 LOGIC: encryption_enabled == False
    """
    if resource.get("resource_type") != "S3":
        return None

    if not resource.get("encryption_enabled", True):
        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="S3",
            rule_id="S3-002",
            title="S3 Bucket Encryption Disabled",
            description=(
                f"Bucket ({resource.get('size_gb', 0)} GB) stores data unencrypted. "
                "If storage media is compromised, data is readable in plain text."
            ),
            severity="HIGH",
            risk_score=70,
            remediation=(
                "1. Enable default encryption: S3 Console → Bucket → Properties → "
                "Default encryption → Enable with SSE-S3 or SSE-KMS. "
                "2. For existing objects, run S3 Batch Operations to re-encrypt."
            ),
            business_impact=(
                "Unencrypted storage fails PCI-DSS, HIPAA, and SOC2 compliance requirements. "
                "In a breach, all stored data is immediately readable by attackers."
            )
        )
    return None


def check_s3_logging(resource: dict) -> Optional[dict]:
    """
    RULE: S3 Access Logging Disabled (MEDIUM)

    Without logging, you cannot:
    - Detect unauthorized access
    - Investigate a breach after it happens
    - Meet audit requirements

    🔦 LOGIC: logging_enabled == False
    """
    if resource.get("resource_type") != "S3":
        return None

    if not resource.get("logging_enabled", True):
        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="S3",
            rule_id="S3-003",
            title="S3 Access Logging Disabled",
            description="No access logs are being collected for this bucket. Cannot audit who accessed data or detect unauthorized access.",
            severity="MEDIUM",
            risk_score=40,
            remediation=(
                "Enable server access logging: S3 Console → Bucket → Properties → "
                "Server access logging → Enable → Set a target log bucket."
            ),
            business_impact=(
                "Without logs, breach investigations are impossible. "
                "Regulatory compliance (HIPAA, SOC2) requires audit trails for data access."
            )
        )
    return None


# ============================================================
# IAM RULES
# ============================================================

def check_iam_mfa(resource: dict) -> Optional[dict]:
    """
    RULE: IAM User MFA Not Enabled (HIGH)

    MFA = Multi-Factor Authentication = requiring a second proof of identity
    (like a phone code) in addition to a password.

    Without MFA, a stolen password = full account access.
    With MFA, a stolen password alone is useless.

    🔦 LOGIC: mfa_enabled == False
    """
    if resource.get("resource_type") != "IAM_USER":
        return None

    if not resource.get("mfa_enabled", True):
        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="IAM_USER",
            rule_id="IAM-001",
            title=f"MFA Not Enabled for IAM User '{resource.get('username', 'unknown')}'",
            description=(
                f"User '{resource.get('username')}' can authenticate with password only. "
                "No second factor is required. If password is stolen (phishing, breach, etc.), "
                "attacker has immediate full access."
            ),
            severity="HIGH",
            risk_score=75,
            remediation=(
                "1. IAM Console → Users → Select user → Security credentials tab. "
                "2. Assign MFA device (virtual — use Google Authenticator or Authy). "
                "3. Create IAM policy requiring MFA for all sensitive actions."
            ),
            business_impact=(
                "Credential theft is the #1 cause of cloud breaches. "
                "Without MFA, a single phishing email can compromise the entire AWS account. "
                "AWS root account access without MFA is a critical compliance violation."
            )
        )
    return None


def check_iam_inactive_user(resource: dict) -> Optional[dict]:
    """
    RULE: IAM User Inactive for 90+ Days (MEDIUM)

    Inactive accounts that still have access are 'ghost doors' into your system.
    If a former employee's account still exists 6 months after they left,
    anyone who gets their credentials can still log in.

    🔦 LOGIC: days_since_last_login > 90
    WHY 90 DAYS? Industry standard for "inactive" definition.
    """
    if resource.get("resource_type") != "IAM_USER":
        return None

    days = resource.get("days_since_last_login", 0)

    if days > 90:
        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="IAM_USER",
            rule_id="IAM-002",
            title=f"Inactive IAM User — {days} Days Without Login",
            description=(
                f"User '{resource.get('username')}' has not logged in for {days} days. "
                "Inactive accounts increase attack surface without providing business value."
            ),
            severity="MEDIUM",
            risk_score=50,
            remediation=(
                "1. Confirm with the user's team if account is still needed. "
                "2. If not needed: Disable console access, delete access keys, eventually delete user. "
                "3. Implement automated lifecycle policy to flag accounts inactive >60 days."
            ),
            business_impact=(
                "Orphaned accounts are a leading cause of insider threat incidents. "
                "Ex-employees retaining access violates SOX, HIPAA, and SOC2 requirements."
            )
        )
    return None


def check_iam_admin_policy(resource: dict) -> Optional[dict]:
    """
    RULE: IAM User Has Admin Policy (HIGH)

    Least Privilege Principle = give users only the access they need, nothing more.
    AdministratorAccess policy = can do ANYTHING in the AWS account.
    Most users don't need this. If their account is compromised, attacker gets everything.

    🔦 LOGIC: has_admin_policy == True
    """
    if resource.get("resource_type") != "IAM_USER":
        return None

    if resource.get("has_admin_policy", False):
        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="IAM_USER",
            rule_id="IAM-003",
            title=f"IAM User Has Excessive Admin Permissions",
            description=(
                f"User '{resource.get('username')}' has the AdministratorAccess policy attached. "
                "This grants unrestricted access to all AWS services and resources."
            ),
            severity="HIGH",
            risk_score=80,
            remediation=(
                "1. Audit what this user actually does. "
                "2. Replace AdministratorAccess with specific policies (e.g., S3ReadOnly, EC2FullAccess). "
                "3. Use IAM Access Analyzer to see what permissions are actually used. "
                "4. Require MFA for any remaining elevated permissions."
            ),
            business_impact=(
                "A compromised admin account can delete all resources, exfiltrate all data, "
                "create backdoor accounts, and cause irreversible damage. "
                "Violates least-privilege principle required by CIS Benchmarks and SOC2."
            )
        )
    return None


def check_iam_old_access_key(resource: dict) -> Optional[dict]:
    """
    RULE: IAM Access Key Never Rotated (MEDIUM)

    Access keys are like passwords for programmatic AWS access.
    Keys that are never changed are more likely to be stolen over time.
    Best practice: rotate keys every 90 days.

    🔦 LOGIC: access_key_age_days > 90
    """
    if resource.get("resource_type") != "IAM_USER":
        return None

    age = resource.get("access_key_age_days", 0)

    if age > 90:
        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="IAM_USER",
            rule_id="IAM-004",
            title=f"Access Key Not Rotated in {age} Days",
            description=(
                f"User '{resource.get('username')}' has an access key that is {age} days old. "
                "Keys should be rotated every 90 days to limit exposure if compromised."
            ),
            severity="MEDIUM",
            risk_score=45,
            remediation=(
                "1. Create a new access key: IAM → User → Security credentials → Create access key. "
                "2. Update all applications/scripts using the old key. "
                "3. Disable the old key, wait 24 hours, then delete it. "
                "4. Automate key rotation reminders via AWS Config rule."
            ),
            business_impact=(
                "Stale access keys are a common initial access vector in cloud breaches. "
                "Keys leaked in code repos, logs, or emails become exploitable after long exposure."
            )
        )
    return None


# ============================================================
# SECURITY GROUP RULES
# ============================================================

def check_sg_open_ssh(resource: dict) -> Optional[dict]:
    """
    RULE: SSH Port 22 Open to Internet (CRITICAL)

    SSH = Secure Shell = remote command-line access to a server.
    If port 22 is open to 0.0.0.0/0 (entire internet), attackers can:
    - Brute force the password
    - Exploit SSH vulnerabilities
    - Use stolen keys to gain shell access

    🔦 LOGIC: any inbound rule with port=22 AND source="0.0.0.0/0"
    """
    if resource.get("resource_type") != "SECURITY_GROUP":
        return None

    rules = resource.get("inbound_rules", [])
    for rule in rules:
        if rule.get("port") == 22 and rule.get("source") == "0.0.0.0/0":
            return create_finding(
                resource_id=resource["resource_id"],
                resource_type="SECURITY_GROUP",
                rule_id="SG-001",
                title="SSH Port 22 Open to Entire Internet",
                description=(
                    "Security group allows SSH access (port 22/TCP) from any IP address (0.0.0.0/0). "
                    "This exposes the server to brute force attacks, credential stuffing, "
                    "and exploitation of SSH vulnerabilities from any location on the internet."
                ),
                severity="CRITICAL",
                risk_score=90,
                remediation=(
                    "IMMEDIATE: Change source from 0.0.0.0/0 to your specific IP or CIDR range. "
                    "Example: Change to 203.0.113.0/32 (your office IP). "
                    "Better: Use AWS Systems Manager Session Manager — eliminates need for port 22 entirely. "
                    "Also: Enable VPN and restrict SSH to VPN subnet only."
                ),
                business_impact=(
                    "Exposed SSH is one of the most commonly attacked surfaces. "
                    "Automated bots scan the internet for open port 22 within minutes of exposure. "
                    "A successful SSH brute force attack provides full server shell access."
                )
            )
    return None


def check_sg_open_rdp(resource: dict) -> Optional[dict]:
    """
    RULE: RDP Port 3389 Open to Internet (CRITICAL)

    RDP = Remote Desktop Protocol = graphical remote access to Windows servers.
    BlueKeep vulnerability (2019) allowed unauthenticated remote code execution via RDP.

    🔦 LOGIC: any inbound rule with port=3389 AND source="0.0.0.0/0"
    """
    if resource.get("resource_type") != "SECURITY_GROUP":
        return None

    rules = resource.get("inbound_rules", [])
    for rule in rules:
        if rule.get("port") == 3389 and rule.get("source") == "0.0.0.0/0":
            return create_finding(
                resource_id=resource["resource_id"],
                resource_type="SECURITY_GROUP",
                rule_id="SG-002",
                title="RDP Port 3389 Open to Entire Internet",
                description=(
                    "Security group allows RDP access (port 3389/TCP) from any IP (0.0.0.0/0). "
                    "RDP is a high-value target for ransomware operators and credential stuffing attacks."
                ),
                severity="CRITICAL",
                risk_score=90,
                remediation=(
                    "1. Restrict RDP to specific IP ranges immediately. "
                    "2. Enable Network Level Authentication (NLA). "
                    "3. Consider using AWS WorkSpaces or VPN instead of direct RDP. "
                    "4. Enable multi-factor for RDP where possible."
                ),
                business_impact=(
                    "Open RDP is the #1 initial access vector for ransomware attacks. "
                    "Average ransomware cost to business: $1.85M (Sophos, 2023). "
                    "Many cyber insurance policies are void if RDP was publicly exposed."
                )
            )
    return None


def check_sg_open_database(resource: dict) -> Optional[dict]:
    """
    RULE: Database Port Open to Internet (HIGH)

    Database ports (MySQL 3306, PostgreSQL 5432, etc.) should NEVER
    be accessible from the internet. They should only accept connections
    from application servers within the same private network.

    🔦 LOGIC: any inbound rule with database port AND source="0.0.0.0/0"
    """
    if resource.get("resource_type") != "SECURITY_GROUP":
        return None

    database_ports = {3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis"}
    rules = resource.get("inbound_rules", [])

    for rule in rules:
        port = rule.get("port")
        if port in database_ports and rule.get("source") == "0.0.0.0/0":
            db_name = database_ports[port]
            return create_finding(
                resource_id=resource["resource_id"],
                resource_type="SECURITY_GROUP",
                rule_id="SG-003",
                title=f"{db_name} Port {port} Exposed to Internet",
                description=(
                    f"Security group exposes {db_name} port {port} to the public internet. "
                    "Database servers should never be directly accessible from outside the VPC."
                ),
                severity="HIGH",
                risk_score=85,
                remediation=(
                    f"1. Remove the 0.0.0.0/0 inbound rule for port {port}. "
                    "2. Allow only the application server's security group as source. "
                    "3. Place databases in private subnets with no internet gateway route. "
                    "4. Use VPC endpoints or private links for cross-account access."
                ),
                business_impact=(
                    "Direct database exposure allows SQL injection attacks without going through "
                    "application-layer protections, bulk data exfiltration, and ransomware targeting databases. "
                    "Customer PII and sensitive data are directly at risk."
                )
            )
    return None


# ============================================================
# RDS RULES
# ============================================================

def check_rds_public(resource: dict) -> Optional[dict]:
    """
    RULE: RDS Database Publicly Accessible (CRITICAL)

    Even with a security group, marking RDS as "publicly accessible" creates
    a DNS endpoint that resolves to a public IP. This is a misconfiguration
    that often goes unnoticed but is consistently flagged in security audits.

    🔦 LOGIC: publicly_accessible == True
    """
    if resource.get("resource_type") != "RDS":
        return None

    if resource.get("publicly_accessible", False):
        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="RDS",
            rule_id="RDS-001",
            title="RDS Database Publicly Accessible",
            description=(
                f"RDS instance ({resource.get('engine')}) has PubliclyAccessible=true. "
                "The database has a public IP address and DNS endpoint accessible from the internet."
            ),
            severity="CRITICAL",
            risk_score=88,
            remediation=(
                "1. Modify RDS instance: Set PubliclyAccessible=false (requires brief downtime). "
                "2. Move to private subnet if currently in public subnet. "
                "3. Use RDS Proxy or VPN for external access requirements. "
                "4. Audit connection logs for unauthorized access attempts."
            ),
            business_impact=(
                "Publicly accessible databases are directly targetable by automated attack tools. "
                "Contains application data, potentially including PII, financial data, or credentials. "
                "GDPR Article 32 requires appropriate technical measures to protect personal data."
            )
        )
    return None


def check_rds_encryption(resource: dict) -> Optional[dict]:
    """
    RULE: RDS Encryption at Rest Disabled (HIGH)

    All major compliance frameworks require database encryption.
    Note: RDS encryption cannot be enabled after creation —
    you must create a new encrypted instance and migrate data.

    🔦 LOGIC: encryption_at_rest == False
    """
    if resource.get("resource_type") != "RDS":
        return None

    if not resource.get("encryption_at_rest", True):
        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="RDS",
            rule_id="RDS-002",
            title="RDS Database Encryption at Rest Disabled",
            description=(
                f"RDS {resource.get('engine')} database stores data unencrypted. "
                "Physical storage media access would expose all database contents."
            ),
            severity="HIGH",
            risk_score=72,
            remediation=(
                "Note: Cannot enable encryption on existing unencrypted instance. "
                "Steps: 1. Take a snapshot of the current instance. "
                "2. Copy the snapshot with encryption enabled. "
                "3. Restore from the encrypted snapshot. "
                "4. Update connection strings and decommission old instance."
            ),
            business_impact=(
                "Unencrypted database storage fails PCI-DSS Requirement 3, HIPAA §164.312, "
                "and SOC2 Common Criteria. A physical breach of AWS data center infrastructure "
                "would expose all stored data."
            )
        )
    return None


def check_rds_backup(resource: dict) -> Optional[dict]:
    """
    RULE: RDS Automated Backups Disabled (HIGH)

    Without backups, data can be permanently lost from:
    - Accidental deletion
    - Ransomware attack
    - Application bugs that corrupt data
    - Human error

    🔦 LOGIC: backup_enabled == False
    """
    if resource.get("resource_type") != "RDS":
        return None

    if not resource.get("backup_enabled", True):
        return create_finding(
            resource_id=resource["resource_id"],
            resource_type="RDS",
            rule_id="RDS-003",
            title="RDS Automated Backups Disabled",
            description=(
                f"RDS {resource.get('engine')} database has no automated backups enabled. "
                "Data cannot be recovered from point-in-time errors or disasters."
            ),
            severity="HIGH",
            risk_score=65,
            remediation=(
                "1. Enable automated backups: set BackupRetentionPeriod to 7-35 days. "
                "2. Also enable manual snapshots before major changes. "
                "3. Test restore process quarterly — untested backups are unreliable."
            ),
            business_impact=(
                "Without backups, a ransomware attack or accidental DROP TABLE is catastrophic. "
                "Recovery time objective (RTO) violation. "
                "Most SLAs and business continuity plans require minimum 7-day backup retention."
            )
        )
    return None


# ============================================================
# MASTER SCANNER
# ============================================================

# Registry of all rules — add new rules here as a tuple of (function, resource_types)
ALL_RULES = [
    check_ec2_underutilized,
    check_ec2_untagged,
    check_s3_public_access,
    check_s3_encryption,
    check_s3_logging,
    check_iam_mfa,
    check_iam_inactive_user,
    check_iam_admin_policy,
    check_iam_old_access_key,
    check_sg_open_ssh,
    check_sg_open_rdp,
    check_sg_open_database,
    check_rds_public,
    check_rds_encryption,
    check_rds_backup,
]


def scan_all_resources(resources: list) -> dict:
    """
    MASTER SCANNER: Runs every resource through every rule.

    Think of this as running a checklist inspection on every item
    in your cloud inventory simultaneously.

    Returns a summary report with all findings organized by severity.
    """
    print(f"🔍 Scanning {len(resources)} resources with {len(ALL_RULES)} rules...")

    all_findings = []

    for resource in resources:
        for rule_func in ALL_RULES:
            finding = rule_func(resource)
            if finding:  # Rule returned a finding (not None)
                all_findings.append(finding)

    # Group findings by severity for easy reporting
    by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in all_findings:
        severity = f.get("severity", "LOW")
        by_severity[severity].append(f)

    print(f"✅ Scan complete!")
    print(f"   🔴 CRITICAL: {len(by_severity['CRITICAL'])}")
    print(f"   🟠 HIGH:     {len(by_severity['HIGH'])}")
    print(f"   🟡 MEDIUM:   {len(by_severity['MEDIUM'])}")
    print(f"   🟢 LOW:      {len(by_severity['LOW'])}")
    print(f"   📊 Total:    {len(all_findings)}")

    return {
        "total_findings": len(all_findings),
        "by_severity": by_severity,
        "all_findings": all_findings
    }


# Test the rule engine directly
if __name__ == "__main__":
    import json
    import sys
    import os
    
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from data.generator import generate_full_dataset

    resources = generate_full_dataset()
    results = scan_all_resources(resources)
    print(f"\n📋 Sample CRITICAL finding:")
    if results["by_severity"]["CRITICAL"]:
        print(json.dumps(results["by_severity"]["CRITICAL"][0], indent=2))