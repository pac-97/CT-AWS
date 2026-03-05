from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import boto3

from services.aws_identity_center import AwsIdentityCenterService


class AwsStateInventoryService:
    def __init__(self, cfg):
        self.cfg = cfg
        self.session = boto3.Session(region_name=cfg.aws_region)
        self.max_items = max(10, min(cfg.inventory_max_items, 5000))

    @property
    def collectors(self) -> dict[str, Any]:
        return {
            'identity_center': self._collect_identity_center,
            'organizations': self._collect_organizations,
            'iam': self._collect_iam,
            'ec2': self._collect_ec2,
            's3': self._collect_s3,
            'cloudtrail': self._collect_cloudtrail,
        }

    def list_modules(self) -> list[str]:
        return sorted(self.collectors.keys())

    def collect(self, requested_modules: list[str] | None = None) -> dict[str, Any]:
        module_names = requested_modules or self.list_modules()
        module_names = [m for m in module_names if m in self.collectors]

        services: dict[str, Any] = {}
        errors: dict[str, str] = {}

        for name in module_names:
            try:
                services[name] = self.collectors[name]()
            except Exception as exc:
                errors[name] = f'{type(exc).__name__}: {exc}'

        return {
            'meta': {
                'region': self.cfg.aws_region,
                'collected_at_utc': datetime.now(UTC).isoformat(),
                'modules_requested': module_names,
                'modules_collected': [k for k in module_names if k in services],
                'errors': errors,
            },
            'services': services,
        }

    def _collect_identity_center(self) -> dict[str, Any]:
        svc = AwsIdentityCenterService(self.cfg)
        permission_sets = svc.list_permission_sets()
        full_permission_sets = [svc.get_permission_set_state(p['arn']) for p in permission_sets[: self.max_items]]

        return {
            'instance': svc.get_instance_metadata(),
            'permission_sets': full_permission_sets,
            'groups': svc.list_groups(limit=min(200, self.max_items)),
            'users': svc.list_users(limit=min(200, self.max_items)),
        }

    def _collect_organizations(self) -> dict[str, Any]:
        org = self.session.client('organizations')

        organization = None
        try:
            organization = org.describe_organization().get('Organization')
        except Exception:
            organization = None

        paginator = org.get_paginator('list_accounts')
        accounts = []
        for page in paginator.paginate():
            for a in page.get('Accounts', []):
                accounts.append(
                    {
                        'id': a.get('Id', ''),
                        'name': a.get('Name', ''),
                        'email': a.get('Email', ''),
                        'status': a.get('Status', ''),
                    }
                )
                if len(accounts) >= self.max_items:
                    return {'organization': organization, 'accounts': accounts}

        return {'organization': organization, 'accounts': accounts}

    def _collect_iam(self) -> dict[str, Any]:
        iam = self.session.client('iam')

        roles = []
        rp = iam.get_paginator('list_roles')
        for page in rp.paginate():
            for r in page.get('Roles', []):
                roles.append(
                    {
                        'name': r.get('RoleName', ''),
                        'arn': r.get('Arn', ''),
                        'path': r.get('Path', ''),
                        'create_date': _dt(r.get('CreateDate')),
                    }
                )
                if len(roles) >= self.max_items:
                    break
            if len(roles) >= self.max_items:
                break

        policies = []
        pp = iam.get_paginator('list_policies')
        for page in pp.paginate(Scope='All'):
            for p in page.get('Policies', []):
                policies.append(
                    {
                        'name': p.get('PolicyName', ''),
                        'arn': p.get('Arn', ''),
                        'description': p.get('Description', '') or '',
                        'update_date': _dt(p.get('UpdateDate')),
                    }
                )
                if len(policies) >= self.max_items:
                    break
            if len(policies) >= self.max_items:
                break

        return {
            'roles': roles,
            'policies': policies,
        }

    def _collect_ec2(self) -> dict[str, Any]:
        ec2 = self.session.client('ec2')

        vpcs = ec2.describe_vpcs().get('Vpcs', [])[: self.max_items]
        subnets = ec2.describe_subnets().get('Subnets', [])[: self.max_items]
        security_groups = ec2.describe_security_groups().get('SecurityGroups', [])[: self.max_items]

        instances = []
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page.get('Reservations', []):
                for inst in reservation.get('Instances', []):
                    instances.append(
                        {
                            'instance_id': inst.get('InstanceId', ''),
                            'state': (inst.get('State') or {}).get('Name', ''),
                            'instance_type': inst.get('InstanceType', ''),
                            'vpc_id': inst.get('VpcId', ''),
                            'subnet_id': inst.get('SubnetId', ''),
                            'launch_time': _dt(inst.get('LaunchTime')),
                        }
                    )
                    if len(instances) >= self.max_items:
                        break
                if len(instances) >= self.max_items:
                    break
            if len(instances) >= self.max_items:
                break

        return {
            'vpcs': [_shape_vpc(v) for v in vpcs],
            'subnets': [_shape_subnet(s) for s in subnets],
            'security_groups': [_shape_sg(sg) for sg in security_groups],
            'instances': instances,
        }

    def _collect_s3(self) -> dict[str, Any]:
        s3 = self.session.client('s3')

        buckets = []
        raw = s3.list_buckets().get('Buckets', [])
        for b in raw[: self.max_items]:
            name = b.get('Name', '')
            location = None
            try:
                location = s3.get_bucket_location(Bucket=name).get('LocationConstraint')
            except Exception:
                location = None

            buckets.append(
                {
                    'name': name,
                    'creation_date': _dt(b.get('CreationDate')),
                    'location': location or 'us-east-1',
                }
            )

        return {'buckets': buckets}

    def _collect_cloudtrail(self) -> dict[str, Any]:
        ct = self.session.client('cloudtrail')
        trails = ct.describe_trails(includeShadowTrails=False).get('trailList', [])

        return {
            'trails': [
                {
                    'name': t.get('Name', ''),
                    'trail_arn': t.get('TrailARN', ''),
                    'home_region': t.get('HomeRegion', ''),
                    's3_bucket_name': t.get('S3BucketName', ''),
                    'is_multi_region_trail': t.get('IsMultiRegionTrail', False),
                }
                for t in trails[: self.max_items]
            ]
        }


def _dt(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return None


def _shape_vpc(v: dict[str, Any]) -> dict[str, Any]:
    return {
        'vpc_id': v.get('VpcId', ''),
        'cidr': v.get('CidrBlock', ''),
        'state': v.get('State', ''),
        'is_default': v.get('IsDefault', False),
    }


def _shape_subnet(s: dict[str, Any]) -> dict[str, Any]:
    return {
        'subnet_id': s.get('SubnetId', ''),
        'vpc_id': s.get('VpcId', ''),
        'cidr': s.get('CidrBlock', ''),
        'az': s.get('AvailabilityZone', ''),
    }


def _shape_sg(sg: dict[str, Any]) -> dict[str, Any]:
    return {
        'group_id': sg.get('GroupId', ''),
        'group_name': sg.get('GroupName', ''),
        'vpc_id': sg.get('VpcId', ''),
        'description': sg.get('Description', ''),
    }
