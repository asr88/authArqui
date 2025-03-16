from app import app, db, User, SafeIP
from werkzeug.security import generate_password_hash

def init_db():
    with app.app_context():
        # Crear las tablas
        db.create_all()
        
        # Verificar si ya existen datos
        if User.query.count() == 0:
            # Crear usuario de ejemplo
            admin = User(username="admin")
            admin.password_hash = generate_password_hash("admin123")
            db.session.add(admin)
            
            # Añadir algunas IPs seguras de ejemplo
            ip1 = SafeIP(
                ip_address="127.0.0.1",
                description="Localhost - Desarrollo",
                added_by="sistema"
            )
            ip2 = SafeIP(
                ip_address="192.168.1.1",
                description="Router local típico",
                added_by="sistema"
            )
            
            db.session.add_all([ip1, ip2])
            db.session.commit()
            
            print("Base de datos inicializada con datos de ejemplo")
        else:
            print("La base de datos ya tiene datos")

if __name__ == "__main__":
    init_db() 