# AWS CIS Compliance Scanner

This scanner is a Python tool that audits an AWS account against a subset of the CIS AWS Foundations Benchmark, using boto3 to check real account configuration and produce a pass/fail report with evidence and remediation guidance for each control.

## Why this project

Manual security audits (checking IAM settings, S3 permissions, security groups one-by-one in the console) don't scale well and can be more error-prone. This project automates a small slice of that process as a way to learn how CIS Benchmark controls map to real AWS API calls, and to practice checking an account's security posture programmatically instead of manually.

## What it checks

| Control | Description |
|---|---|
| CIS 1.5 | Root account has MFA enabled |
| CIS 1.4 | No root account access keys exist |
| CIS 1.16 | IAM password policy meets minimum length/complexity requirements |
| CIS 2.1 | CloudTrail is enabled across all regions |
| Custom (S3) | All S3 buckets have Block Public Access fully enabled |
| CIS 5.1 / 5.2 | No security groups allow unrestricted SSH/RDP ingress from `0.0.0.0/0` |

Each check queries live AWS account data via boto3, evaluates it against the control's requirement, and logs a pass/fail result with the underlying evidence and (if failed) a specific remediation step.

## Before & after

When I first ran the scanner against a newly created AWS account, it caught two gaps:

**Before — 4/6 passing**

<img width="988" height="442" alt="before" src="https://github.com/user-attachments/assets/beb5c297-a4b8-430c-ac00-cc3383aecddb" />

- No IAM password policy was set
- CloudTrail not enabled

I fixed both directly in the AWS console by changing the password policy to a 14-character-minimum with full complexity requirements, and created a multi-region CloudTrail trail. I then re-ran the scanner.

**After — 6/6 passing**

<img width="909" height="359" alt="after" src="https://github.com/user-attachments/assets/f28ce70b-57d9-4c68-8ec9-7f54b389ba41" />


Re-running the same script after making those changes was a useful way to confirm the fixes actually took effect.


## Security design decisions

- **The scanner runs under a dedicated IAM user** (`compliance-scanner`) with only the AWS-managed `ReadOnlyAccess` policy attached, rather than the admin credentials used for manual setup. This follows the **principle of least privilege**: since the tool only needs to read configuration, it isn't given permission to change anything, so a bug in the code or a leaked credential couldn't be used to modify the account.
- Credentials are loaded from a local `.env` file (excluded from version control by `.gitignore`).
- A separate administrative IAM user (with MFA) is used for manual console work; it is not the credential the script uses.

## Tech stack
- Python 3
- boto3 (AWS SDK for Python)
- python-dotenv

## Setup

```bash
git clone <this-repo-url>
cd aws-compliance-scanner
python3 -m venv venv
source venv/bin/activate
pip install boto3 python-dotenv
```

Create a `.env` file in the project root:

```
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
AWS_DEFAULT_REGION=us-west-2
```

The IAM user tied to these credentials should have (at minimum) the AWS-managed `ReadOnlyAccess` policy attached.

## Usage

```bash
python3 scanner.py
```

This prints a pass/fail summary to the terminal and writes a full result set to `report.json`.


## Possible future additions to scan for

- IAM users without MFA enabled
- Access keys older than 90 days (rotation policy)
- Unused/inactive IAM credentials
- HTML/PDF report generation for audit-ready output

## Note

Built as a learning project to understand CIS Benchmark controls and AWS security fundamentals. It checks a subset of the full CIS AWS Foundations Benchmark, not the complete standard.
