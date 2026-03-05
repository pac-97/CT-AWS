from __future__ import annotations

import json
from typing import Any

from services.aws_identity_center import AwsIdentityCenterService


def build_permission_set_plan(svc: AwsIdentityCenterService, desired_state: dict[str, Any]) -> dict[str, Any]:
    desired_items = desired_state.get('permission_sets', [])
    if not isinstance(desired_items, list):
        raise ValueError('desired_state.permission_sets must be a list')

    actual_items = svc.list_permission_sets()
    actual_by_name = {item['name'].lower(): item for item in actual_items}

    actions: list[dict[str, Any]] = []
    no_change = 0

    desired_names: set[str] = set()
    for item in desired_items:
        if not isinstance(item, dict):
            raise ValueError('Each permission set item must be an object')

        name = str(item.get('name', '')).strip()
        if not name:
            raise ValueError('Each permission set must include a non-empty name')
        desired_names.add(name.lower())

        desired = _normalize_desired_item(item)
        actual_ref = actual_by_name.get(name.lower())

        if not actual_ref:
            actions.append(
                {
                    'action': 'create_permission_set',
                    'name': desired['name'],
                    'desired': desired,
                }
            )
            continue

        state = svc.get_permission_set_state(actual_ref['arn'])
        changes = _diff_permission_set(state, desired)
        if changes:
            actions.append(
                {
                    'action': 'update_permission_set',
                    'name': desired['name'],
                    'permission_set_arn': actual_ref['arn'],
                    'changes': changes,
                    'desired': desired,
                }
            )
        else:
            no_change += 1

    unmanaged = [
        {'name': item['name'], 'arn': item['arn']}
        for item in actual_items
        if item['name'].lower() not in desired_names
    ]

    return {
        'summary': {
            'create': sum(1 for a in actions if a['action'] == 'create_permission_set'),
            'update': sum(1 for a in actions if a['action'] == 'update_permission_set'),
            'no_change': no_change,
            'unmanaged': len(unmanaged),
        },
        'actions': actions,
        'unmanaged_permission_sets': unmanaged,
    }


def apply_permission_set_plan(svc: AwsIdentityCenterService, plan: dict[str, Any]) -> dict[str, Any]:
    actions = plan.get('actions', [])
    if not isinstance(actions, list):
        raise ValueError('plan.actions must be a list')

    results = []
    for action in actions:
        desired = action.get('desired', {})
        result = svc.upsert_permission_set(
            name=desired.get('name', ''),
            description=desired.get('description', ''),
            session_duration=desired.get('session_duration', 'PT4H'),
            managed_policy_arns=desired.get('managed_policy_arns', []),
            inline_policy=desired.get('inline_policy'),
            provision_account_ids=desired.get('provision_account_ids', []),
        )
        results.append(
            {
                'name': desired.get('name', ''),
                'action': action.get('action'),
                'result': result,
            }
        )

    return {
        'applied': len(results),
        'results': results,
    }


def _normalize_desired_item(item: dict[str, Any]) -> dict[str, Any]:
    managed = item.get('managed_policy_arns', [])
    if not isinstance(managed, list):
        raise ValueError(f"managed_policy_arns for {item.get('name', '<unknown>')} must be a list")

    provision = item.get('provision_account_ids', [])
    if not isinstance(provision, list):
        raise ValueError(f"provision_account_ids for {item.get('name', '<unknown>')} must be a list")

    inline_policy = item.get('inline_policy')
    if isinstance(inline_policy, dict):
        inline_policy = json.dumps(inline_policy, separators=(',', ':'), sort_keys=True)
    elif isinstance(inline_policy, str):
        inline_policy = _normalize_policy_json(inline_policy)
    elif inline_policy is None:
        inline_policy = None
    else:
        raise ValueError(f"inline_policy for {item.get('name', '<unknown>')} must be object, string, or null")

    return {
        'name': str(item.get('name', '')).strip(),
        'description': str(item.get('description', '')).strip(),
        'session_duration': str(item.get('session_duration', 'PT4H')).strip(),
        'managed_policy_arns': sorted({str(p).strip() for p in managed if str(p).strip()}),
        'inline_policy': inline_policy,
        'provision_account_ids': sorted({str(a).strip() for a in provision if str(a).strip()}),
    }


def _diff_permission_set(actual: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    changes: dict[str, Any] = {}

    if (actual.get('description') or '') != desired['description']:
        changes['description'] = {'actual': actual.get('description') or '', 'desired': desired['description']}

    if (actual.get('session_duration') or 'PT4H') != desired['session_duration']:
        changes['session_duration'] = {'actual': actual.get('session_duration') or 'PT4H', 'desired': desired['session_duration']}

    actual_policies = sorted(actual.get('managed_policy_arns', []))
    if actual_policies != desired['managed_policy_arns']:
        changes['managed_policy_arns'] = {
            'actual': actual_policies,
            'desired': desired['managed_policy_arns'],
        }

    actual_policy = _normalize_policy_json(actual.get('inline_policy') or '') if actual.get('inline_policy') else None
    desired_policy = _normalize_policy_json(desired.get('inline_policy') or '') if desired.get('inline_policy') else None
    if actual_policy != desired_policy:
        changes['inline_policy'] = {
            'actual': actual_policy,
            'desired': desired_policy,
        }

    return changes


def _normalize_policy_json(policy_text: str) -> str:
    data = json.loads(policy_text)
    return json.dumps(data, separators=(',', ':'), sort_keys=True)
