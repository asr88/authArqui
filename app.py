from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo de Usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    logins = db.relationship('LoginHistory', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Modelo para el historial de inicios de sesión
class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 puede ser largo
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)

# Crear las tablas en la base de datos
with app.app_context():
    db.create_all()

# Rutas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Verificar si el usuario ya existe
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('El nombre de usuario ya existe.')
            return redirect(url_for('register'))
        
        # Crear nuevo usuario
        new_user = User(username=username)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('¡Registro exitoso! Ahora puedes iniciar sesión.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        # Registrar el intento de inicio de sesión
        ip_address = request.remote_addr
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            
            # Guardar el historial de inicio de sesión exitoso
            login_record = LoginHistory(user_id=user.id, ip_address=ip_address, success=True)
            db.session.add(login_record)
            db.session.commit()
            
            flash('¡Inicio de sesión exitoso!')
            return redirect(url_for('dashboard'))
        else:
            # Guardar el historial de inicio de sesión fallido
            if user:
                login_record = LoginHistory(user_id=user.id, ip_address=ip_address, success=False)
                db.session.add(login_record)
                db.session.commit()
            
            flash('Usuario o contraseña incorrectos.')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Debes iniciar sesión primero.')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    login_history = LoginHistory.query.filter_by(user_id=user.id).order_by(LoginHistory.timestamp.desc()).all()
    
    return render_template('dashboard.html', user=user, login_history=login_history)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Has cerrado sesión correctamente.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
