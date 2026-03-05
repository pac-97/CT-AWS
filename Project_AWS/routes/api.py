import json

from flask import Blueprint, current_app, request

from services.audit_store import list_events, log_event
from services.aws_identity_center import AwsIdentityCenterService
from services.aws_state_inventory import AwsStateInventoryService
from services.drift_planner import apply_permission_set_plan, build_permission_set_plan

api_bp = Blueprint('api', __name__)


def _svc() -> AwsIdentityCenterService:
    return AwsIdentityCenterService(current_app.config['APP_CONFIG'])


def _inventory() -> AwsStateInventoryService:
    return AwsStateInventoryService(current_app.config['APP_CONFIG'])


def _request_ip() -> str | None:
    return request.headers.get('X-Forwarded-For', request.remote_addr)


def _actor() -> str:
    return request.headers.get('X-Actor', 'local-operator')


def _audit(action: str, target: str | None, status: str, payload=None, result=None, error_text: str | None = None):
    log_event(
        current_app.config['APP_CONFIG'],
        actor_username=_actor(),
        actor_role='operator',
        action=action,
        target=target,
        status=status,
        request_ip=_request_ip(),
        payload=payload,
        result=result,
        error_text=error_text,
    )


@api_bp.get('/bootstrap')
def bootstrap():
    svc = _svc()
    return {
        'instance': svc.get_instance_metadata(),
        'accounts': svc.list_accounts(),
        'permission_sets': svc.list_permission_sets(),
        'groups': svc.list_groups(limit=200),
        'users': svc.list_users(limit=200),
    }


@api_bp.get('/iam/managed-policies')
def managed_policies():
    svc = _svc()
    limit = request.args.get('limit', '500')
    scope = request.args.get('scope', 'All')

    try:
        safe_limit = int(limit)
    except ValueError:
        safe_limit = 500

    try:
        items = svc.list_managed_policies(scope=scope, limit=safe_limit)
        return {'items': items}
    except Exception as exc:
        return {'error': str(exc)}, 500


@api_bp.get('/state/import/modules')
def state_import_modules():
    return {'modules': _inventory().list_modules()}


@api_bp.get('/state/import')
def import_state():
    modules_raw = request.args.get('modules', '').strip()
    modules = [m.strip() for m in modules_raw.split(',') if m.strip()] if modules_raw else None

    try:
        state = _inventory().collect(requested_modules=modules)
        result = {
            'modules_collected': state['meta'].get('modules_collected', []),
            'errors': state['meta'].get('errors', {}),
        }
        _audit('state.import', 'snapshot', 'success', payload={'modules': modules}, result=result)
        return {'state': state}
    except Exception as exc:
        _audit('state.import', 'snapshot', 'failed', payload={'modules': modules}, error_text=str(exc))
        return {'error': str(exc)}, 500


@api_bp.post('/permission-sets/upsert')
def upsert_permission_set():
    payload = request.get_json(force=True)
    svc = _svc()

    name = payload.get('name', '').strip()
    if not name:
        return {'error': 'Permission set name is required'}, 400

    try:
        policy_doc = payload.get('inline_policy', '').strip()
        if policy_doc:
            json.loads(policy_doc)

        result = svc.upsert_permission_set(
            name=name,
            description=payload.get('description', ''),
            session_duration=payload.get('session_duration', 'PT4H'),
            managed_policy_arns=payload.get('managed_policy_arns', []),
            inline_policy=policy_doc or None,
            provision_account_ids=payload.get('provision_account_ids') or current_app.config['APP_CONFIG'].default_provision_accounts,
        )
        _audit('permission_set.upsert', name, 'success', payload=payload, result=result)
        return result
    except json.JSONDecodeError as exc:
        _audit('permission_set.upsert', name, 'failed', payload=payload, error_text=f'invalid_json:{exc}')
        return {'error': f'Invalid inline policy JSON: {exc}'}, 400
    except Exception as exc:
        _audit('permission_set.upsert', name, 'failed', payload=payload, error_text=str(exc))
        return {'error': str(exc)}, 500


@api_bp.post('/assignments')
def create_assignment():
    payload = request.get_json(force=True)
    svc = _svc()

    required = ['account_id', 'permission_set_arn', 'principal_id', 'principal_type']
    missing = [key for key in required if not payload.get(key)]
    if missing:
        return {'error': f'Missing fields: {", ".join(missing)}'}, 400

    target = f"{payload.get('account_id')}::{payload.get('principal_type')}::{payload.get('principal_id')}"
    try:
        result = svc.create_account_assignment(
            account_id=payload['account_id'],
            permission_set_arn=payload['permission_set_arn'],
            principal_id=payload['principal_id'],
            principal_type=payload['principal_type'],
        )
        _audit('assignment.create', target, 'success', payload=payload, result=result)
        return result
    except Exception as exc:
        _audit('assignment.create', target, 'failed', payload=payload, error_text=str(exc))
        return {'error': str(exc)}, 500


@api_bp.post('/drift/plan')
def drift_plan():
    payload = request.get_json(force=True)
    desired_state = payload.get('desired_state')
    if isinstance(desired_state, str):
        desired_state = json.loads(desired_state)

    if not isinstance(desired_state, dict):
        return {'error': 'desired_state must be an object'}, 400

    try:
        plan = build_permission_set_plan(_svc(), desired_state)
        _audit('drift.plan', 'permission_sets', 'success', payload=desired_state, result=plan.get('summary'))
        return plan
    except Exception as exc:
        _audit('drift.plan', 'permission_sets', 'failed', payload=desired_state, error_text=str(exc))
        return {'error': str(exc)}, 400


@api_bp.post('/drift/apply')
def drift_apply():
    payload = request.get_json(force=True)
    desired_state = payload.get('desired_state')
    if isinstance(desired_state, str):
        desired_state = json.loads(desired_state)

    if not isinstance(desired_state, dict):
        return {'error': 'desired_state must be an object'}, 400

    try:
        svc = _svc()
        plan = build_permission_set_plan(svc, desired_state)
        result = apply_permission_set_plan(svc, plan)
        response = {
            'plan_summary': plan.get('summary', {}),
            'apply_result': result,
        }
        _audit('drift.apply', 'permission_sets', 'success', payload=desired_state, result=response)
        return response
    except Exception as exc:
        _audit('drift.apply', 'permission_sets', 'failed', payload=desired_state, error_text=str(exc))
        return {'error': str(exc)}, 400


@api_bp.get('/audit')
def audit_logs():
    limit = request.args.get('limit', '200')
    try:
        safe_limit = int(limit)
    except ValueError:
        safe_limit = 200

    return {
        'events': list_events(current_app.config['APP_CONFIG'], limit=safe_limit),
    }
