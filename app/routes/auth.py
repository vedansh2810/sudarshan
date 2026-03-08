from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from app.models.user import User
from app import limiter

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.authenticate(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        
        if not all([username, email, password, confirm]):
            flash('All fields are required.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        elif len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
        else:
            if User.get_by_username(username):
                flash('Username already taken.', 'error')
            elif User.get_by_email(email):
                flash('Email already registered.', 'error')
            else:
                user_id = User.create(username, email, password)
                if user_id:
                    session['user_id'] = user_id
                    session['username'] = username
                    flash('Account created successfully!', 'success')
                    return redirect(url_for('dashboard.index'))
                else:
                    flash('Registration failed. Please try again.', 'error')
    
    return render_template('auth/register.html')

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))
