# AWS Control Plane Web App

Modern multi-page Flask web application to manage AWS from a service-catalog UI.

## What this project does

- Service-catalog home with widget-style AWS modules
- Dedicated IAM Identity Center workspace page
- Dedicated AWS state-import page
- Creates/updates permission sets from website
- Attaches existing managed policies discovered from AWS IAM
- Supports account assignments (group/user to account + permission set)
- Drift detection with Terraform-style `plan` / `apply`
- Full modular AWS state import (multi-service) into reusable JSON snapshot
- Audit logs in SQLite

## Multi-page routes

- `/` -> service catalog home
- `/services/iam-identity-center` -> IAM Identity Center operations
- `/services/state-import` -> full AWS state import

## Import modules currently supported

- `identity_center`
- `organizations`
- `iam`
- `ec2`
- `s3`
- `cloudtrail`

Use API:
- `GET /api/state/import/modules` -> list available modules
- `GET /api/state/import?modules=iam,ec2,s3` -> import selected modules

If one module fails due to permissions, other modules still import; errors are returned in `state.meta.errors`.

## Architecture

- `app.py`: Flask entry point
- `config.py`: env config
- `routes/web.py`: page routes
- `routes/api.py`: APIs for bootstrap, policies, import, plan/apply
- `services/aws_identity_center.py`: Identity Center operations
- `services/aws_state_inventory.py`: pluggable full-state collectors
- `services/drift_planner.py`: drift engine
- `services/audit_store.py`: audit DB
- `templates/` + `static/`: frontend

## Requirements

- Python 3.13+
- AWS credentials available on host (instance profile recommended on EC2)
- IAM permissions for selected modules (examples):
  - `sso-admin:*`, `identitystore:*`
  - `organizations:ListAccounts`, `organizations:DescribeOrganization`
  - `iam:ListRoles`, `iam:ListPolicies`
  - `ec2:Describe*`
  - `s3:ListAllMyBuckets`, `s3:GetBucketLocation`
  - `cloudtrail:DescribeTrails`

## Local setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

Open `http://localhost:5000`.

## Env options

- `INVENTORY_MAX_ITEMS=500` limits per-service import volume to keep UI/API responsive.

## Deploy on EC2

1. Attach IAM role to EC2 with required permissions.
2. Set `.env` values.
3. Install dependencies.
4. Run:

```powershell
gunicorn --bind 0.0.0.0:5000 app:app
```

5. Place Nginx/ALB in front for TLS + domain.
