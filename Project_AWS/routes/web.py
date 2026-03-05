from flask import Blueprint, render_template

web_bp = Blueprint('web', __name__)


@web_bp.get('/')
def home():
    return render_template('home.html', page_id='home')


@web_bp.get('/services/iam-identity-center')
def iam_identity_center_page():
    return render_template('iam_identity_center.html', page_id='iam-identity-center')


@web_bp.get('/services/state-import')
def state_import_page():
    return render_template('state_import.html', page_id='state-import')
