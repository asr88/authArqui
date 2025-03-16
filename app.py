from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import ipaddress

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
    is_suspicious = db.Column(db.Boolean, default=False)  # Nuevo campo para marcar IPs sospechosas

# Modelo para IPs seguras
class SafeIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    description = db.Column(db.String(200))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.String(80))

# Funciones para verificar IPs
def is_valid_ip(ip):
    """Verifica si una cadena es una dirección IP válida"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_ip_safe(ip_address):
    """Verifica si una IP está en la lista de IPs seguras"""
    return SafeIP.query.filter_by(ip_address=ip_address).first() is not None

# Crear las tablas en la base de datos
with app.app_context():
    db.create_all()

# Registrar la función is_ip_safe como global para las plantillas
@app.context_processor
def utility_processor():
    return {
        'is_ip_safe': is_ip_safe
    }

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
    # Si es una solicitud GET, renderiza el formulario de login
    if request.method == 'GET':
        return render_template('login.html')
    
    # Detecta si es una solicitud de API o web
    is_api_request = request.is_json or request.headers.get('Accept') == 'application/json'
    
    # Para solicitudes POST (tanto desde web como desde API)
    if is_api_request and request.is_json:
        # Si los datos vienen en formato JSON
        data = request.json
        username = data.get('username')
        password = data.get('password')
    else:
        # Si los datos vienen en formato form-data
        username = request.form.get('username')
        password = request.form.get('password')
    
    # Verificar si faltan credenciales
    if not username or not password:
        if is_api_request:
            return jsonify({"error": "Username and password are required"}), 400
        flash('El nombre de usuario y la contraseña son obligatorios.')
        return render_template('login.html')
    
    user = User.query.filter_by(username=username).first()
    
    # Registrar el intento de inicio de sesión
    ip_address = request.remote_addr
    ip_suspicious = not is_ip_safe(ip_address)
    
    if user and user.check_password(password):
        session['user_id'] = user.id
        
        # Guardar el historial de inicio de sesión exitoso
        login_record = LoginHistory(
            user_id=user.id, 
            ip_address=ip_address, 
            success=True,
            is_suspicious=ip_suspicious
        )
        db.session.add(login_record)
        db.session.commit()
        
        # Si es una solicitud de API, devuelve JSON
        if is_api_request:
            return jsonify({
                "success": True,
                "message": "Login successful",
                "user_id": user.id,
                "username": user.username,
                "ip_status": "suspicious" if ip_suspicious else "safe"
            })
        
        # Para solicitudes web
        if ip_suspicious:
            flash('¡Advertencia! Inicio de sesión desde una IP no reconocida como segura.')
        flash('¡Inicio de sesión exitoso!')
        return redirect(url_for('dashboard'))
    else:
        # Guardar el historial de inicio de sesión fallido
        if user:
            login_record = LoginHistory(
                user_id=user.id, 
                ip_address=ip_address, 
                success=False,
                is_suspicious=ip_suspicious
            )
            db.session.add(login_record)
            db.session.commit()
        
        # Si es una solicitud de API, devuelve JSON
        if is_api_request:
            return jsonify({"error": "Invalid username or password"}), 401
        
        # Para solicitudes web
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

# Rutas para administrar IPs seguras
@app.route('/safe_ips')
def safe_ips():
    if 'user_id' not in session:
        flash('Debes iniciar sesión primero.')
        return redirect(url_for('login'))
    
    # Verificar si es administrador (puedes implementar esta lógica)
    user = User.query.get(session['user_id'])
    
    safe_ips = SafeIP.query.order_by(SafeIP.added_at.desc()).all()
    return render_template('safe_ips.html', safe_ips=safe_ips)

@app.route('/add_safe_ip', methods=['GET', 'POST'])
def add_safe_ip():
    if 'user_id' not in session:
        flash('Debes iniciar sesión primero.')
        return redirect(url_for('login'))
    
    # Verificar si es administrador (puedes implementar esta lógica)
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')
        description = request.form.get('description', '')
        
        if not is_valid_ip(ip_address):
            flash('Dirección IP inválida.')
            return redirect(url_for('add_safe_ip'))
        
        # Verificar si la IP ya existe
        existing_ip = SafeIP.query.filter_by(ip_address=ip_address).first()
        if existing_ip:
            flash('Esta IP ya está en la lista de IPs seguras.')
            return redirect(url_for('safe_ips'))
        
        # Añadir IP segura
        safe_ip = SafeIP(
            ip_address=ip_address,
            description=description,
            added_by=user.username
        )
        db.session.add(safe_ip)
        db.session.commit()
        
        flash(f'IP {ip_address} añadida a la lista de IPs seguras.')
        return redirect(url_for('safe_ips'))
    
    return render_template('add_safe_ip.html')

@app.route('/delete_safe_ip/<int:ip_id>', methods=['POST'])
def delete_safe_ip(ip_id):
    if 'user_id' not in session:
        flash('Debes iniciar sesión primero.')
        return redirect(url_for('login'))
    
    # Verificar si es administrador (puedes implementar esta lógica)
    user = User.query.get(session['user_id'])
    
    safe_ip = SafeIP.query.get_or_404(ip_id)
    db.session.delete(safe_ip)
    db.session.commit()
    
    flash(f'IP {safe_ip.ip_address} eliminada de la lista de IPs seguras.')
    return redirect(url_for('safe_ips'))

@app.route('/suspicious_logins')
def suspicious_logins():
    if 'user_id' not in session:
        flash('Debes iniciar sesión primero.')
        return redirect(url_for('login'))
    
    # Verificar si es administrador (puedes implementar esta lógica)
    user = User.query.get(session['user_id'])
    
    suspicious_logins = LoginHistory.query.filter_by(is_suspicious=True).order_by(LoginHistory.timestamp.desc()).all()
    return render_template('suspicious_logins.html', suspicious_logins=suspicious_logins)

@app.route('/api/login', methods=['POST'])
def api_login():
    """
    Endpoint exclusivo para APIs que siempre devuelve JSON
    """
    # Obtener datos de la solicitud (acepta tanto JSON como form-data)
    if request.is_json:
        data = request.json
        username = data.get('username')
        password = data.get('password')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
    
    # Verificar credenciales
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    
    # Buscar usuario
    user = User.query.filter_by(username=username).first()
    
    # Verificar IP
    ip_address = request.remote_addr
    ip_suspicious = not is_ip_safe(ip_address)
    
    # Verificar autenticación
    if not user or not user.check_password(password):
        # Registrar inicio de sesión fallido
        if user:
            login_record = LoginHistory(
                user_id=user.id,
                ip_address=ip_address,
                success=False,
                is_suspicious=ip_suspicious
            )
            db.session.add(login_record)
            db.session.commit()
        
        return jsonify({"error": "Invalid username or password"}), 401
    
    # Si llegamos aquí, la autenticación fue exitosa
    # Guardar historial de inicio de sesión
    login_record = LoginHistory(
        user_id=user.id,
        ip_address=ip_address,
        success=True,
        is_suspicious=ip_suspicious
    )
    db.session.add(login_record)
    db.session.commit()
    
    # Respuesta exitosa
    return jsonify({
        "success": True,
        "message": "Login successful",
        "user_id": user.id,
        "username": user.username,
        "ip_status": "suspicious" if ip_suspicious else "safe"
    })

if __name__ == '__main__':
    app.run(debug=True)
