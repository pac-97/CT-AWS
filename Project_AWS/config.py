import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


def _csv_env(name: str) -> list[str]:
    raw = os.getenv(name, '').strip()
    if not raw:
        return []
    return [part.strip() for part in raw.split(',') if part.strip()]


@dataclass(frozen=True)
class Config:
    flask_env: str = os.getenv('FLASK_ENV', 'production')
    secret_key: str = os.getenv('SECRET_KEY', 'change-me')
    port: int = int(os.getenv('PORT', '5000'))

    aws_region: str = os.getenv('AWS_REGION', 'us-east-1')
    sso_instance_arn: str | None = os.getenv('SSO_INSTANCE_ARN')
    identity_store_id: str | None = os.getenv('IDENTITY_STORE_ID')
    default_provision_accounts: list[str] = None

    app_db_path: str = os.getenv('APP_DB_PATH', 'data/control_plane.db')
    inventory_max_items: int = int(os.getenv('INVENTORY_MAX_ITEMS', '500'))

    def __post_init__(self):
        object.__setattr__(self, 'default_provision_accounts', _csv_env('DEFAULT_PROVISION_ACCOUNTS'))
