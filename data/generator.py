"""
DATA GENERATOR - Creates fake but realistic AWS cloud resources
Think of this as a "world builder" for our simulation.
We intentionally inject bad configurations so our rule engine has things to catch.

REAL-WORLD ANALOGY: Like a movie set designer who builds realistic props —
everything looks real, but it's all controlled for the story we want to tell.
"""

import json
import random
from faker import Faker
from datetime import datetime, timedelta

# Faker creates realistic fake data (names, IDs, regions, etc.)
fake = Faker()

# ============================================================
# CONFIGURATION: What percentage of resources have problems?
# We make ~35% of resources have at least one issue
# This makes the demo dramatic and realistic
# ============================================================
MISCONFIGURATION_RATE = 0.35


def random_timestamp(days_back=90):
    """
    Creates a random datetime within the last X days.
    WHY: We want resources to have different "last seen" times,
    mimicking a real environment where things change over time.
    """
    start = datetime.now() - timedelta(days=days_back)
    random_days = random.randint(0, days_back)
    return (start + timedelta(days=random_days)).isoformat()


def generate_ec2_instances(count=80):
    """
    Generates fake EC2 instances (virtual servers in AWS).
    EC2 = Elastic Compute Cloud = basically a rented computer in the cloud.

    INTENTIONAL PROBLEMS WE INJECT:
    - Low CPU usage (wasted money — paying for a server nobody uses)
    - Old instance types (inefficient, costs more)
    - Long running with no purpose tag
    """

    # These are real AWS instance types with their hourly costs
    # t3.micro = tiny/cheap, m5.xlarge = medium/expensive, etc.
    instance_types = {
        "t3.micro": 0.0104,
        "t3.small": 0.0208,
        "t3.medium": 0.0416,
        "t3.large": 0.0832,
        "m5.large": 0.096,
        "m5.xlarge": 0.192,
        "m5.2xlarge": 0.384,
        "c5.xlarge": 0.17,
        "r5.large": 0.126,
    }

    # Real AWS regions where servers can live
    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

    instances = []

    for i in range(count):
        instance_type = random.choice(list(instance_types.keys()))
        hourly_cost = instance_types[instance_type]

        # Running hours in the last 30 days (max = 720 hours = 24h x 30 days)
        running_hours = random.randint(1, 720)

        # CPU utilization — how busy is this server?
        # INTENTIONAL MISCONFIGURATION: 35% chance of very low CPU (wasted money)
        if random.random() < MISCONFIGURATION_RATE:
            cpu_avg = random.uniform(0.5, 5.0)   # 0.5% to 5% — basically idle!
        else:
            cpu_avg = random.uniform(20, 85)      # 20% to 85% — normal usage

        instance = {
            "resource_id": f"i-{fake.lexify('??????????', letters='abcdef0123456789')}",
            "resource_type": "EC2",
            "instance_type": instance_type,
            "region": random.choice(regions),
            "state": random.choice(["running", "running", "running", "stopped"]),
            "cpu_avg_percent": round(cpu_avg, 2),
            "running_hours_30d": running_hours,
            "hourly_cost_usd": hourly_cost,
            "monthly_cost_usd": round(hourly_cost * running_hours, 2),
            # Tags help identify purpose — missing tags = unknown purpose = risk
            "has_purpose_tag": random.random() > 0.3,
            "last_seen": random_timestamp(),
            "scan_timestamp": datetime.now().isoformat()
        }
        instances.append(instance)

    return instances


def generate_s3_buckets(count=60):
    """
    Generates fake S3 buckets (cloud file storage in AWS).
    S3 = Simple Storage Service = basically folders in the cloud.

    INTENTIONAL PROBLEMS WE INJECT:
    - Public access enabled (CRITICAL — anyone on internet can read your files!)
    - Encryption disabled (data stored in plain text)
    - Versioning disabled (no backup if files are deleted)
    - Logging disabled (can't audit who accessed what)
    """

    buckets = []

    for i in range(count):
        # INTENTIONAL MISCONFIGURATION: public access is a CRITICAL security risk
        # We inject this in ~20% of buckets — even 1 is a huge problem
        public_access = random.random() < 0.20

        # If public, more likely to also have other problems (realistic pattern)
        if public_access:
            encryption = random.random() > 0.6   # 40% chance no encryption
            logging_enabled = random.random() > 0.5
        else:
            encryption = random.random() > 0.15  # 15% chance no encryption
            logging_enabled = random.random() > 0.25

        bucket = {
            "resource_id": f"s3-{fake.slug()}-{random.randint(100, 999)}",
            "resource_type": "S3",
            "region": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
            "public_access_blocked": not public_access,  # True = SAFE, False = DANGER
            "encryption_enabled": encryption,
            "versioning_enabled": random.random() > 0.4,
            "logging_enabled": logging_enabled,
            "size_gb": round(random.uniform(0.1, 5000), 2),
            "object_count": random.randint(1, 1000000),
            "last_accessed": random_timestamp(180),
            "scan_timestamp": datetime.now().isoformat()
        }
        buckets.append(bucket)

    return buckets


def generate_iam_users(count=50):
    """
    Generates fake IAM users (Identity and Access Management).
    IAM = who is allowed to do what in AWS.

    INTENTIONAL PROBLEMS WE INJECT:
    - MFA not enabled (no two-factor auth — easy to hack if password stolen)
    - Unused accounts (ghost users — security risk if compromised)
    - Overly permissive policies (admin access for someone who doesn't need it)
    - Old access keys never rotated
    """

    users = []

    for i in range(count):
        # INTENTIONAL MISCONFIGURATION: ~40% of users have no MFA
        mfa_enabled = random.random() > 0.40

        # Days since last login — inactive users are security risks
        days_since_login = random.randint(0, 365)
        is_inactive = days_since_login > 90  # 90+ days = inactive

        # Key age — access keys should be rotated regularly
        access_key_age_days = random.randint(1, 400)

        user = {
            "resource_id": f"iam-{fake.user_name()}-{random.randint(100, 999)}",
            "resource_type": "IAM_USER",
            "username": fake.user_name(),
            "mfa_enabled": mfa_enabled,
            "days_since_last_login": days_since_login,
            "is_inactive": is_inactive,
            "access_key_age_days": access_key_age_days,
            # INTENTIONAL MISCONFIGURATION: Some users have full admin (dangerous)
            "has_admin_policy": random.random() < 0.15,
            "policy_count": random.randint(1, 8),
            "last_seen": random_timestamp(),
            "scan_timestamp": datetime.now().isoformat()
        }
        users.append(user)

    return users


def generate_security_groups(count=70):
    """
    Generates fake Security Groups (AWS firewall rules).
    Security Groups = rules that control which traffic can reach your servers.

    0.0.0.0/0 means "anyone in the entire internet" — very dangerous for
    sensitive ports like SSH (22), RDP (3389), or database ports.

    INTENTIONAL PROBLEMS WE INJECT:
    - SSH port 22 open to entire internet
    - RDP port 3389 open to entire internet
    - Database ports open to internet
    """

    # Ports and what they're used for
    port_risk_map = {
        22: "SSH",      # Remote server access — CRITICAL if open to world
        3389: "RDP",    # Windows remote desktop — CRITICAL if open to world
        3306: "MySQL",  # Database — HIGH if open to world
        5432: "PostgreSQL",  # Database — HIGH if open to world
        27017: "MongoDB",    # Database — HIGH if open to world
        6379: "Redis",       # Cache/DB — HIGH if open to world
        80: "HTTP",     # Web traffic — usually OK
        443: "HTTPS",   # Secure web — usually OK
    }

    groups = []

    for i in range(count):
        open_to_world = random.random() < MISCONFIGURATION_RATE

        if open_to_world:
            # Pick a risky port to expose
            risky_ports = [22, 3389, 3306, 5432, 27017, 6379]
            exposed_port = random.choice(risky_ports)
            inbound_rules = [{
                "port": exposed_port,
                "protocol": "tcp",
                "source": "0.0.0.0/0",  # THE DANGER: entire internet
                "service": port_risk_map.get(exposed_port, "Unknown")
            }]
        else:
            # Safe: only allow specific IPs or internal traffic
            inbound_rules = [{
                "port": random.choice([80, 443]),
                "protocol": "tcp",
                "source": f"10.0.{random.randint(0,255)}.0/24",  # Private IP range = safe
                "service": "Internal"
            }]

        group = {
            "resource_id": f"sg-{fake.lexify('????????', letters='abcdef0123456789')}",
            "resource_type": "SECURITY_GROUP",
            "region": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
            "inbound_rules": inbound_rules,
            "open_to_internet": open_to_world,
            "scan_timestamp": datetime.now().isoformat()
        }
        groups.append(group)

    return groups


def generate_rds_instances(count=30):
    """
    Generates fake RDS instances (managed databases in AWS).
    RDS = Relational Database Service = managed MySQL/PostgreSQL/etc.

    INTENTIONAL PROBLEMS:
    - Publicly accessible (database reachable from internet)
    - Encryption disabled
    - Backups disabled (data loss risk)
    - Multi-AZ disabled (no high availability — single point of failure)
    """

    db_engines = ["mysql", "postgres", "mariadb", "oracle", "sqlserver"]

    dbs = []

    for i in range(count):
        # INTENTIONAL MISCONFIGURATION: publicly accessible database
        publicly_accessible = random.random() < 0.25

        db = {
            "resource_id": f"rds-{fake.slug()}-{random.randint(10, 99)}",
            "resource_type": "RDS",
            "engine": random.choice(db_engines),
            "region": random.choice(["us-east-1", "us-west-2", "eu-west-1"]),
            "publicly_accessible": publicly_accessible,
            "encryption_at_rest": random.random() > 0.20,
            "backup_enabled": random.random() > 0.15,
            "multi_az": random.random() > 0.45,
            "instance_class": random.choice(["db.t3.micro", "db.t3.small", "db.m5.large"]),
            "storage_gb": random.randint(20, 1000),
            "scan_timestamp": datetime.now().isoformat()
        }
        dbs.append(db)

    return dbs


def generate_full_dataset():
    """
    Master function: generates ALL resource types and combines into one dataset.
    This is what we'll load into Elasticsearch.
    """
    print("🏗️  Generating simulated AWS cloud dataset...")

    all_resources = []
    all_resources.extend(generate_ec2_instances(80))
    all_resources.extend(generate_s3_buckets(60))
    all_resources.extend(generate_iam_users(50))
    all_resources.extend(generate_security_groups(70))
    all_resources.extend(generate_rds_instances(30))

    print(f"✅ Generated {len(all_resources)} cloud resources")
    print(f"   - EC2 Instances: 80")
    print(f"   - S3 Buckets:    60")
    print(f"   - IAM Users:     50")
    print(f"   - Security Groups: 70")
    print(f"   - RDS Instances:  30")

    # Save to file so we can inspect it
    with open("data/sample_data.json", "w") as f:
        json.dump(all_resources, f, indent=2)

    print("💾  Saved to data/sample_data.json")
    return all_resources


# Run this file directly to generate data
# Command: python data/generator.py
if __name__ == "__main__":
    data = generate_full_dataset()
    print(f"\n📊 Sample resource: {json.dumps(data[0], indent=2)}")