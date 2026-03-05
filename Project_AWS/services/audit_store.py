from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def _connect(db_path: str) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_audit_db(cfg) -> None:
    conn = _connect(cfg.app_db_path)
    try:
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                actor_username TEXT,
                actor_role TEXT,
                action TEXT NOT NULL,
                target TEXT,
                status TEXT NOT NULL,
                request_ip TEXT,
                payload_json TEXT,
                result_json TEXT,
                error_text TEXT
            )
            '''
        )
        conn.commit()
    finally:
        conn.close()


def log_event(
    cfg,
    *,
    actor_username: str | None,
    actor_role: str | None,
    action: str,
    target: str | None,
    status: str,
    request_ip: str | None,
    payload: dict | list | str | None = None,
    result: dict | list | str | None = None,
    error_text: str | None = None,
) -> None:
    conn = _connect(cfg.app_db_path)
    try:
        conn.execute(
            '''
            INSERT INTO audit_logs(
                actor_username,
                actor_role,
                action,
                target,
                status,
                request_ip,
                payload_json,
                result_json,
                error_text
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                actor_username,
                actor_role,
                action,
                target,
                status,
                request_ip,
                _json_or_none(payload),
                _json_or_none(result),
                error_text,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def list_events(cfg, limit: int = 200) -> list[dict]:
    safe_limit = max(1, min(limit, 1000))
    conn = _connect(cfg.app_db_path)
    try:
        rows = conn.execute(
            '''
            SELECT id, ts_utc, actor_username, actor_role, action, target, status, request_ip,
                   payload_json, result_json, error_text
            FROM audit_logs
            ORDER BY id DESC
            LIMIT ?
            ''',
            (safe_limit,),
        ).fetchall()
    finally:
        conn.close()

    return [
        {
            'id': r['id'],
            'timestamp': r['ts_utc'],
            'actor_username': r['actor_username'],
            'actor_role': r['actor_role'],
            'action': r['action'],
            'target': r['target'],
            'status': r['status'],
            'request_ip': r['request_ip'],
            'payload': _parse_json(r['payload_json']),
            'result': _parse_json(r['result_json']),
            'error_text': r['error_text'],
        }
        for r in rows
    ]


def _json_or_none(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def _parse_json(value: str | None):
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value
