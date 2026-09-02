"""
AWS - Compliance Scanner
Checks an AWS account against a subset of CIS AWS Foundations Benchmark controls.
"""
import os
import json
import boto3
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

session = boto3.Session(
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_DEFAULT_REGION", "us-west-2"),
)

iam = session.client("iam")
s3 = session.client("s3")
ec2 = session.client("ec2")
cloudtrail = session.client("cloudtrail")

results = []


def add_result(control_id, description, passed, evidence, remediation=""):
    results.append({
        "control_id": control_id,
        "description": description,
        "status": "PASS" if passed else "FAIL",
        "evidence": evidence,
        "remediation": remediation if not passed else "",
    })


# CIS 1.5 — Ensure MFA is enabled for the root account
# ---------------------------------------------------------------------------

def check_root_mfa():
    summary = iam.get_account_summary()["SummaryMap"]
    mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
    add_result(
        control_id="CIS 1.5",
        description="Root account has MFA enabled",
        passed=mfa_enabled,
        evidence=f"AccountMFAEnabled = {summary.get('AccountMFAEnabled')}",
        remediation="Enable an MFA device on the root account via IAM console.",
    )


# CIS 1.4 — Ensure no root account access keys exist
# ---------------------------------------------------------------------------
def check_root_access_keys():
    summary = iam.get_account_summary()["SummaryMap"]
    key_count = summary.get("AccountAccessKeysPresent", 0)
    add_result(
        control_id="CIS 1.4",
        description="No root account access keys exist",
        passed=key_count == 0,
        evidence=f"AccountAccessKeysPresent = {key_count}",
        remediation="Delete any root account access keys via IAM console.",
    )


# CIS 1.16 — Ensure IAM password policy meets minimum requirements
# --------------------------------------------------------------------
def check_password_policy():
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        checks = {
            "MinimumPasswordLength >= 14": policy.get("MinimumPasswordLength", 0) >= 14,
            "RequireSymbols": policy.get("RequireSymbols", False),
            "RequireNumbers": policy.get("RequireNumbers", False),
            "RequireUppercaseCharacters": policy.get("RequireUppercaseCharacters", False),
            "RequireLowercaseCharacters": policy.get("RequireLowercaseCharacters", False),
        }
        passed = all(checks.values())
        evidence = json.dumps({k: v for k, v in checks.items()})
    except iam.exceptions.NoSuchEntityException:
        passed = False
        evidence = "No password policy is set on this account."

    add_result(
        control_id="CIS 1.16",
        description="IAM password policy meets minimum complexity requirements",
        passed=passed,
        evidence=evidence,
        remediation="Set an account password policy under IAM > Account settings.",
    )


# CIS 2.1 — Ensure CloudTrail is enabled in all regions
# --------------------------------------------------------------------
def check_cloudtrail_enabled():
    trails = cloudtrail.describe_trails()["trailList"]
    multi_region_trails = [t for t in trails if t.get("IsMultiRegionTrail")]
    passed = len(multi_region_trails) > 0
    evidence = f"{len(trails)} trail(s) found; {len(multi_region_trails)} multi-region."
    add_result(
        control_id="CIS 2.1",
        description="CloudTrail is enabled in all regions",
        passed=passed,
        evidence=evidence,
        remediation="Create a multi-region trail in the CloudTrail console.",
    )


# CIS 2.1.1 — Ensure S3 bucket used for CloudTrail logs is not publicly accessible
#             (bundled here as: no S3 buckets in the account are publicly accessible)
# --------------------------------------------------------------------------------
def check_s3_public_access():
    buckets = s3.list_buckets()["Buckets"]
    public_buckets = []

    for bucket in buckets:
        name = bucket["Name"]
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all(pab.values())
        except s3.exceptions.ClientError:
            fully_blocked = False  # no public access block config = not confirmed safe

        if not fully_blocked:
            public_buckets.append(name)

    passed = len(public_buckets) == 0
    evidence = f"{len(buckets)} bucket(s) checked. Not fully blocked: {public_buckets}"
    add_result(
        control_id="CIS S3.1 (custom)",
        description="All S3 buckets have Block Public Access fully enabled",
        passed=passed,
        evidence=evidence,
        remediation="Enable 'Block all public access' on each flagged bucket.",
    )


# ---------------------------------------------------------------------------
# CIS 5.1 — Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
# CIS 5.2 — same, for port 3389 (RDP)
# ---------------------------------------------------------------------------
def check_open_security_groups():
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    risky_ports = {22: "SSH", 3389: "RDP"}
    offenders = []

    for sg in sgs:
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    for port, name in risky_ports.items():
                        if from_port is not None and from_port <= port <= (to_port or from_port):
                            offenders.append(f"{sg['GroupId']} ({sg['GroupName']}) - {name}")

    passed = len(offenders) == 0
    evidence = f"{len(sgs)} security group(s) checked. Offenders: {offenders}"
    add_result(
        control_id="CIS 5.1 / 5.2",
        description="No security groups allow unrestricted SSH/RDP ingress from 0.0.0.0/0",
        passed=passed,
        evidence=evidence,
        remediation="Restrict SSH/RDP ingress rules to specific trusted IP ranges.",
    )


# ---------------------------------------------------------------------------
# Run everything
# ---------------------------------------------------------------------------
def run_all_checks():
    check_root_mfa()
    check_root_access_keys()
    check_password_policy()
    check_cloudtrail_enabled()
    check_s3_public_access()
    check_open_security_groups()


def print_summary():
    passed = sum(1 for r in results if r["status"] == "PASS")
    total = len(results)
    print(f"\n{'='*60}")
    print(f"AWS CIS Compliance Scan — {passed}/{total} controls passed")
    print(f"{'='*60}\n")
    for r in results:
        symbol = "✅" if r["status"] == "PASS" else "❌"
        print(f"{symbol} [{r['control_id']}] {r['description']}")
        print(f"    Evidence: {r['evidence']}")
        if r["remediation"]:
            print(f"    Fix: {r['remediation']}")
        print()


def save_json_report(path="report.json"):
    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Full JSON report saved to {path}")


if __name__ == "__main__":
    run_all_checks()
    print_summary()
    save_json_report()