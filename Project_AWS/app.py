from flask import Flask

from config import Config
from routes.api import api_bp
from routes.web import web_bp
from services.audit_store import init_audit_db


def create_app() -> Flask:
    cfg = Config()
    app = Flask(__name__)
    app.config['SECRET_KEY'] = cfg.secret_key
    app.config['APP_CONFIG'] = cfg

    init_audit_db(cfg)

    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    @app.get('/health')
    def health():
        return {'status': 'ok'}

    return app


app = create_app()


if __name__ == '__main__':
    cfg = app.config['APP_CONFIG']
    app.run(host='0.0.0.0', port=cfg.port, debug=cfg.flask_env == 'development')
