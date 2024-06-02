from flask import (
  Blueprint, render_template, request, 
  flash, redirect, url_for, send_from_directory, 
  current_app, make_response, session
)
from .models import Photo
from sqlalchemy import asc, text
from . import db
import os
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from functools import wraps

# Define a Blueprint for the main routes
main = Blueprint('main', __name__)

# This is called when the home page is rendered. It fetches all images sorted by filename.
@main.route('/')
def homepage():
  photos = db.session.query(Photo).order_by(asc(Photo.file))
  return render_template('index.html', photos=photos)

# Serve uploaded files from the uploads directory
@main.route('/uploads/<name>')
def display_file(name):
  return send_from_directory(current_app.config["UPLOAD_DIR"], name)

# Upload a new photo
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

    newPhoto = Photo(name=request.form['user'], 
                    caption=request.form['caption'],
                    description=request.form['description'],
                    file=file.filename)
    db.session.add(newPhoto)
    flash('New Photo %s Successfully Created' % newPhoto.name)
    db.session.commit()
    return redirect(url_for('main.homepage'))
  else:
    return render_template('upload.html')

# This is called when clicking on Edit. Goes to the edit page.
@main.route('/photo/<int:photo_id>/edit/', methods=['GET', 'POST'])
def editPhoto(photo_id):
  editedPhoto = db.session.query(Photo).filter_by(id=photo_id).one()
  if request.method == 'POST':
    if request.form['user']:
      editedPhoto.name = request.form['user']
      editedPhoto.caption = request.form['caption']
      editedPhoto.description = request.form['description']
      db.session.add(editedPhoto)
      db.session.commit()
      flash('Photo Successfully Edited %s' % editedPhoto.name)
      return redirect(url_for('main.homepage'))
  else:
    return render_template('edit.html', photo=editedPhoto)

# This is called when clicking on Delete. 
@main.route('/photo/<int:photo_id>/delete/', methods=['GET', 'POST'])
def deletePhoto(photo_id):
  fileResults = db.session.execute(text('select file from photo where id = ' + str(photo_id)))
  filename = fileResults.first()[0]
  filepath = os.path.join(current_app.config["UPLOAD_DIR"], filename)
  os.unlink(filepath)
  db.session.execute(text('delete from photo where id = ' + str(photo_id)))
  db.session.commit()
  
  flash('Photo id %s Successfully Deleted' % photo_id)
  return redirect(url_for('main.homepage'))

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
  return User.query.filter_by(username=username, password=password).first()

# Login route for handling user login
@main.route('/login', methods=['POST'])
def login():
  user = authenticate(request.form['username'], request.form['password'])
  if user:
    token = generate_auth_token(user.id)
    response = make_response(redirect(url_for('main.homepage')))
    response.set_cookie('auth_token', token)
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
