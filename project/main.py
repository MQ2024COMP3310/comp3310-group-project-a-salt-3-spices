from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app, session
from .models import Photo, Comment, User
from sqlalchemy import asc, text
from . import db
import os
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
import datetime

# Define a Blueprint for the main routes
main = Blueprint('main', __name__)

@main.route('/photo/<int:photo_id>/', methods=['GET', 'POST'])
def photo_detail(photo_id):
    photo = db.session.query(Photo).filter_by(id=photo_id).one()
    comments = db.session.query(Comment).filter_by(photo_id=photo_id).all()
    if request.method == 'POST':
        if 'user_id' not in session:
            flash('You need to be logged in to comment.', 'error')
            return redirect(url_for('main.photo_detail', photo_id=photo_id))

        content = request.form['comment']
        if not content.strip():
            flash('Comment cannot be empty.', 'error')
            return redirect(url_for('main.photo_detail', photo_id=photo_id))
        
        # Sanitize user input
        content = secure_filename(content)

        new_comment = Comment(
            photo_id=photo_id,
            user_id=session['user_id'],
            content=content,
            timestamp=datetime.datetime.now()
        )
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment added successfully.', 'success')
        return redirect(url_for('main.photo_detail', photo_id=photo_id))
    return render_template('photo_detail.html', photo=photo, comments=comments)

# Ensure all input is sanitized to prevent XSS
@main.route('/upload/', methods=['GET', 'POST'])
def newPhoto():
    if request.method == 'POST':
        file = None
        if "fileToUpload" in request.files:
            file = request.files.get("fileToUpload")
        else:
            flash("Invalid request!", "error")

        if not file or not file.filename:
            flash("No file selected!", "error")
            return redirect(request.url)

        # Sanitize the filename before saving the file
        filepath = os.path.join(current_app.config["UPLOAD_DIR"], secure_filename(file.filename))
        file.save(filepath)

        newPhoto = Photo(
            name=request.form['user'],
            caption=request.form['caption'],
            description=request.form['description'],
            file=secure_filename(file.filename)
        )
        db.session.add(newPhoto)
        flash('New Photo %s Successfully Created' % newPhoto.name)
        db.session.commit()
        return redirect(url_for('main.homepage'))
    else:
        return render_template('upload.html')

# Secure Session Management
@main.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.homepage'))

# Generate an authentication token using a serializer
def generate_auth_token(user_id):
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(user_id, salt='auth-token')

# Placeholder authentication function
def authenticate(username, password):
    # Replace with actual authentication logic
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return user
    return None

# Login route for handling user login
@main.route('/login', methods=['POST'])
def login():
    user = authenticate(request.form['username'], request.form['password'])
    if user:
        token = generate_auth_token(user.id)
        response = make_response(redirect(url_for('main.homepage')))
        response.set_cookie('auth_token', token, secure=True, httponly=True)
        return response
    else:
        flash('Invalid username or password', 'error')
        return redirect(url_for('main.login'))

# Role-Based Access Control (RBAC)
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required.', 'error')
            return redirect(url_for('main.homepage'))
        return f(*args, **kwargs)
    return decorated_function

# Admin route to manage photos
@main.route('/admin/photos')
@admin_required
def manage_photos():
    photos = db.session.query(Photo).all()
    return render_template('admin_photos.html', photos=photos)

# Error Handling
@main.app_errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@main.app_errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403

# Password Recovery
@main.route('/password-recovery', methods=['GET', 'POST'])
def password_recovery():
    if request.method == 'POST':
        email = request.form['email']
        # Add logic for sending password recovery email or 2FA code
        flash('Password recovery instructions sent to your email.', 'info')
        return redirect(url_for('main.homepage'))
    return render_template('password_recovery.html')
