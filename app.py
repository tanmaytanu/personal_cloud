# ✅ app.py (Flask App)

from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory
#from flask_mysqldb import MySQL
import mysql.connector
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# 🔧 MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'cloud_storage'

#mysql = MySQL(app)

# 🔐 Login Manager Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 📁 Upload folder
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ✅ User Class
class User(UserMixin):
    def __init__(self, id, username, password, is_admin):
        self.id = id
        self.username = username
        self.password = password
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username, password, is_admin FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    if user:
        return User(*user)
    return None

# 🔑 Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, username, password, is_admin FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        if user and check_password_hash(user[2], password):
            login_user(User(*user))
            return redirect(url_for('index'))
    return render_template('login.html')

# 🚪 Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# 📝 Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        mysql.connection.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

# 🏠 Dashboard
@app.route('/')
@login_required
def index():
    return render_template('index.html')

# 📂 Upload
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    filename = secure_filename(file.filename)
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    os.makedirs(user_folder, exist_ok=True)
    file.save(os.path.join(user_folder, filename))
    return redirect(url_for('index'))

# 📄 List Files
@app.route('/files')
@login_required
def files():
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
    os.makedirs(user_folder, exist_ok=True)
    return jsonify(os.listdir(user_folder))

# 📥 Download - FIXED
@app.route('/download/<filename>')
@login_required
def download(filename):
    user_folder = current_user.username
    return send_from_directory(
        os.path.join(app.config['UPLOAD_FOLDER'], user_folder),
        filename,
        as_attachment=True
    )

# 🌐 Open - FIXED
@app.route('/open/<filename>')
@login_required
def open_file(filename):
    user_folder = current_user.username
    return send_from_directory(
        os.path.join(app.config['UPLOAD_FOLDER'], user_folder),
        filename
    )

# ❌ Delete
@app.route('/delete/<filename>', methods=['DELETE'])
@login_required
def delete(filename):
    path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username, filename)
    if os.path.exists(path):
        os.remove(path)
        return jsonify({'message': 'File deleted'})
    return jsonify({'error': 'File not found'})

# 🛠️ Admin Panel
@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, username FROM users WHERE is_admin = FALSE")
    users = cur.fetchall()
    return render_template('admin.html', users=users)

@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    username = request.form['username']
    password = generate_password_hash(request.form['password'])
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
    mysql.connection.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM users WHERE id = %s AND is_admin = FALSE", (user_id,))
    mysql.connection.commit()
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    app.run(debug=True)
