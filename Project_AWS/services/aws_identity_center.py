from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import boto3


@dataclass
class InstanceContext:
    instance_arn: str
    identity_store_id: str


class AwsIdentityCenterService:
    def __init__(self, cfg):
        self.cfg = cfg
        self.session = boto3.Session(region_name=cfg.aws_region)
        self.sso_admin = self.session.client('sso-admin')
        self.identitystore = self.session.client('identitystore')
        self.organizations = self.session.client('organizations')
        self.iam = self.session.client('iam')
        self._instance_context: InstanceContext | None = None

    def _resolve_instance_context(self) -> InstanceContext:
        if self._instance_context:
            return self._instance_context

        if self.cfg.sso_instance_arn and self.cfg.identity_store_id:
            self._instance_context = InstanceContext(
                instance_arn=self.cfg.sso_instance_arn,
                identity_store_id=self.cfg.identity_store_id,
            )
            return self._instance_context

        instances = self.sso_admin.list_instances().get('Instances', [])
        if not instances:
            raise RuntimeError('No IAM Identity Center instance found in this account/region')

        instance = instances[0]
        self._instance_context = InstanceContext(
            instance_arn=instance['InstanceArn'],
            identity_store_id=instance['IdentityStoreId'],
        )
        return self._instance_context

    def get_instance_metadata(self) -> dict[str, str]:
        ctx = self._resolve_instance_context()
        return {
            'instance_arn': ctx.instance_arn,
            'identity_store_id': ctx.identity_store_id,
            'region': self.cfg.aws_region,
        }

    def list_accounts(self) -> list[dict[str, str]]:
        paginator = self.organizations.get_paginator('list_accounts')
        rows: list[dict[str, str]] = []
        for page in paginator.paginate():
            for account in page.get('Accounts', []):
                rows.append(
                    {
                        'id': account['Id'],
                        'name': account['Name'],
                        'email': account.get('Email', ''),
                        'status': account.get('Status', ''),
                    }
                )
        return sorted(rows, key=lambda x: x['name'].lower())

    def list_permission_sets(self) -> list[dict[str, str]]:
        ctx = self._resolve_instance_context()
        paginator = self.sso_admin.get_paginator('list_permission_sets')

        out: list[dict[str, str]] = []
        for page in paginator.paginate(InstanceArn=ctx.instance_arn):
            for arn in page.get('PermissionSets', []):
                details = self.sso_admin.describe_permission_set(
                    InstanceArn=ctx.instance_arn,
                    PermissionSetArn=arn,
                )['PermissionSet']
                out.append(
                    {
                        'arn': arn,
                        'name': details['Name'],
                        'description': details.get('Description', ''),
                        'session_duration': details.get('SessionDuration', 'PT4H'),
                    }
                )

        return sorted(out, key=lambda x: x['name'].lower())

    def get_permission_set_state(self, permission_set_arn: str) -> dict[str, Any]:
        ctx = self._resolve_instance_context()
        details = self.sso_admin.describe_permission_set(
            InstanceArn=ctx.instance_arn,
            PermissionSetArn=permission_set_arn,
        )['PermissionSet']

        inline_policy = None
        try:
            policy_res = self.sso_admin.get_inline_policy_for_permission_set(
                InstanceArn=ctx.instance_arn,
                PermissionSetArn=permission_set_arn,
            )
            inline_policy = policy_res.get('InlinePolicy') or None
        except self.sso_admin.exceptions.ResourceNotFoundException:
            inline_policy = None

        return {
            'arn': permission_set_arn,
            'name': details['Name'],
            'description': details.get('Description', ''),
            'session_duration': details.get('SessionDuration', 'PT4H'),
            'managed_policy_arns': sorted(self._list_attached_managed_policies(permission_set_arn)),
            'inline_policy': inline_policy,
        }

    def list_groups(self, limit: int = 100) -> list[dict[str, str]]:
        ctx = self._resolve_instance_context()
        resp = self.identitystore.list_groups(
            IdentityStoreId=ctx.identity_store_id,
            MaxResults=min(limit, 100),
        )
        groups = resp.get('Groups', [])
        return [
            {
                'id': g['GroupId'],
                'name': g.get('DisplayName', ''),
                'description': g.get('Description', ''),
            }
            for g in groups
        ]

    def list_users(self, limit: int = 100) -> list[dict[str, str]]:
        ctx = self._resolve_instance_context()
        resp = self.identitystore.list_users(
            IdentityStoreId=ctx.identity_store_id,
            MaxResults=min(limit, 100),
        )
        users = resp.get('Users', [])
        return [
            {
                'id': u['UserId'],
                'username': u.get('UserName', ''),
                'display_name': u.get('DisplayName', ''),
                'email': _extract_user_email(u),
            }
            for u in users
        ]

    def list_managed_policies(self, scope: str = 'All', limit: int = 500) -> list[dict[str, str]]:
        safe_limit = max(1, min(limit, 2000))
        paginator = self.iam.get_paginator('list_policies')

        rows: list[dict[str, str]] = []
        for page in paginator.paginate(Scope=scope):
            for p in page.get('Policies', []):
                rows.append(
                    {
                        'arn': p.get('Arn', ''),
                        'name': p.get('PolicyName', ''),
                        'scope': p.get('Arn', '').split(':')[4] and 'Local' or 'AWS',
                        'description': p.get('Description', '') or '',
                    }
                )
                if len(rows) >= safe_limit:
                    return sorted(rows, key=lambda x: x['name'].lower())

        return sorted(rows, key=lambda x: x['name'].lower())

    def export_state_snapshot(self) -> dict[str, Any]:
        permission_sets = self.list_permission_sets()
        full_permission_sets: list[dict[str, Any]] = []
        for p in permission_sets:
            state = self.get_permission_set_state(p['arn'])
            state['provision_account_ids'] = []
            full_permission_sets.append(state)

        return {
            'version': 1,
            'region': self.cfg.aws_region,
            'instance': self.get_instance_metadata(),
            'permission_sets': full_permission_sets,
            'managed_policies': self.list_managed_policies(scope='All', limit=1000),
            'accounts': self.list_accounts(),
            'groups': self.list_groups(limit=200),
            'users': self.list_users(limit=200),
        }

    def upsert_permission_set(
        self,
        *,
        name: str,
        description: str,
        session_duration: str,
        managed_policy_arns: list[str],
        inline_policy: str | None,
        provision_account_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        ctx = self._resolve_instance_context()

        existing = self._find_permission_set_by_name(name)
        if existing:
            perm_arn = existing['arn']
            self.sso_admin.update_permission_set(
                InstanceArn=ctx.instance_arn,
                PermissionSetArn=perm_arn,
                Description=description,
                SessionDuration=session_duration,
            )
            action = 'updated'
        else:
            created = self.sso_admin.create_permission_set(
                InstanceArn=ctx.instance_arn,
                Name=name,
                Description=description,
                SessionDuration=session_duration,
            )
            perm_arn = created['PermissionSet']['PermissionSetArn']
            action = 'created'

        desired = {p.strip() for p in managed_policy_arns if p.strip()}
        current = self._list_attached_managed_policies(perm_arn)

        for policy_arn in sorted(desired - current):
            self.sso_admin.attach_managed_policy_to_permission_set(
                InstanceArn=ctx.instance_arn,
                PermissionSetArn=perm_arn,
                ManagedPolicyArn=policy_arn,
            )

        for policy_arn in sorted(current - desired):
            self.sso_admin.detach_managed_policy_from_permission_set(
                InstanceArn=ctx.instance_arn,
                PermissionSetArn=perm_arn,
                ManagedPolicyArn=policy_arn,
            )

        if inline_policy:
            self.sso_admin.put_inline_policy_to_permission_set(
                InstanceArn=ctx.instance_arn,
                PermissionSetArn=perm_arn,
                InlinePolicy=inline_policy,
            )
        else:
            try:
                self.sso_admin.delete_inline_policy_from_permission_set(
                    InstanceArn=ctx.instance_arn,
                    PermissionSetArn=perm_arn,
                )
            except self.sso_admin.exceptions.ResourceNotFoundException:
                pass

        provisioned = []
        for account_id in provision_account_ids or []:
            result = self.sso_admin.provision_permission_set(
                InstanceArn=ctx.instance_arn,
                PermissionSetArn=perm_arn,
                TargetType='AWS_ACCOUNT',
                TargetId=account_id,
            )
            provisioned.append(
                {
                    'account_id': account_id,
                    'request_id': result['PermissionSetProvisioningStatus']['RequestId'],
                    'status': result['PermissionSetProvisioningStatus']['Status'],
                }
            )

        return {
            'status': 'ok',
            'action': action,
            'permission_set_arn': perm_arn,
            'provisioning': provisioned,
        }

    def create_account_assignment(
        self,
        *,
        account_id: str,
        permission_set_arn: str,
        principal_id: str,
        principal_type: str,
    ) -> dict[str, Any]:
        ctx = self._resolve_instance_context()
        result = self.sso_admin.create_account_assignment(
            InstanceArn=ctx.instance_arn,
            TargetType='AWS_ACCOUNT',
            TargetId=account_id,
            PermissionSetArn=permission_set_arn,
            PrincipalType=principal_type,
            PrincipalId=principal_id,
        )
        status = result['AccountAssignmentCreationStatus']
        return {
            'status': 'ok',
            'request_id': status['RequestId'],
            'assignment_status': status['Status'],
        }

    def _find_permission_set_by_name(self, name: str) -> dict[str, str] | None:
        for item in self.list_permission_sets():
            if item['name'].lower() == name.lower():
                return item
        return None

    def _list_attached_managed_policies(self, permission_set_arn: str) -> set[str]:
        ctx = self._resolve_instance_context()
        paginator = self.sso_admin.get_paginator('list_managed_policies_in_permission_set')

        arns: set[str] = set()
        for page in paginator.paginate(
            InstanceArn=ctx.instance_arn,
            PermissionSetArn=permission_set_arn,
        ):
            for item in page.get('AttachedManagedPolicies', []):
                arns.add(item['Arn'])
        return arns


def _extract_user_email(user: dict[str, Any]) -> str:
    emails = user.get('Emails', [])
    if not emails:
        return ''
    primary = next((e for e in emails if e.get('Primary')), None)
    pick = primary or emails[0]
    return pick.get('Value', '')
