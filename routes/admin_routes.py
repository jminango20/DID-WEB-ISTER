"""
Admin panel routes.

Provides a web interface for the issuer to:
- Log in with admin credentials
- View all issued credentials
- Issue new credentials to students

All routes require admin authentication via Flask session.
"""

from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, jsonify

from config import config

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def require_admin(f):
    """Decorator: redirect to login if not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated


@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page."""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if username == config.ADMIN_USERNAME and password == config.ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Credenciales incorrectas', 'error')

    return render_template('admin/login.html')


@admin_bp.route('/logout')
def logout():
    """Clear admin session."""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin.login'))


@admin_bp.route('/')
@admin_bp.route('/dashboard')
@require_admin
def dashboard():
    """Admin dashboard showing all issued credentials."""
    from utils.database import get_supabase_client
    try:
        supabase = get_supabase_client()
        result = supabase.table('credentials') \
            .select('claim_id, student_name, student_email, course_name, issued_at, claimed') \
            .order('issued_at', desc=True) \
            .execute()
        credentials = result.data or []
    except Exception as e:
        flash(f'Database error: {str(e)}', 'error')
        credentials = []

    return render_template('admin/dashboard.html', credentials=credentials)


@admin_bp.route('/issue', methods=['GET', 'POST'])
@require_admin
def issue_credential():
    """Form to issue a new credential to a student."""
    if request.method == 'GET':
        return render_template('admin/issue_credential.html')

    # POST: process the form
    student_name = request.form.get('student_name', '').strip()
    student_email = request.form.get('student_email', '').strip()
    student_id = request.form.get('student_id', '').strip()
    course_name = request.form.get('course_name', '').strip()
    completion_date = request.form.get('completion_date', '').strip()
    grade = request.form.get('grade', '').strip()

    # Basic validation
    if not all([student_name, student_email, student_id, course_name, completion_date]):
        flash('Todos los campos excepto la calificación son obligatorios', 'error')
        return render_template('admin/issue_credential.html')

    try:
        from utils.crypto import load_private_key
        from utils.credential import create_verifiable_credential
        from utils.database import get_supabase_client

        private_key = load_private_key(config.PRIVATE_KEY_PATH)

        credential, claim_id = create_verifiable_credential(
            student_name=student_name,
            student_email=student_email,
            student_id=student_id,
            course_name=course_name,
            completion_date=completion_date,
            grade=grade,
            issuer_did=config.DID_METHOD,
            private_key=private_key,
        )

        # Store in Supabase
        supabase = get_supabase_client()
        supabase.table('credentials').insert({
            'claim_id': claim_id,
            'credential_type': 'EducationalCredential',
            'student_name': student_name,
            'student_email': student_email,
            'student_id': student_id,
            'course_name': course_name,
            'completion_date': completion_date,
            'grade': grade,
            'credential_data': credential,
        }).execute()

        claim_url = request.host_url.rstrip('/') + f'/wallet/claim/{claim_id}'
        flash(f'¡Credencial emitida! URL de reclamo: {claim_url}', 'success')
        return redirect(url_for('admin.dashboard'))

    except FileNotFoundError:
        flash('Clave privada no encontrada. Ejecuta: python generate_keys.py', 'error')
    except Exception as e:
        flash(f'Error issuing credential: {str(e)}', 'error')

    return render_template('admin/issue_credential.html')
