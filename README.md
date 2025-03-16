# Servicio de Autenticación con Registro de IP

Un servicio de autenticación simple pero seguro desarrollado con Flask que registra las direcciones IP de los usuarios cuando intentan iniciar sesión, para mayor seguridad y seguimiento.

## Características

- Registro de usuarios
- Inicio de sesión seguro
- Almacenamiento de contraseñas con hash
- Registro de direcciones IP en cada intento de inicio de sesión
- Panel de control con historial de inicios de sesión
- Seguimiento de inicios de sesión fallidos

## Requisitos

- Python 3.7+
- Flask
- Flask-SQLAlchemy
- Otras dependencias (ver requirements.txt)

## Instalación

1. Clonar el repositorio o descargar los archivos

2. Crear y activar un entorno virtual:

```bash
# Crear entorno virtual
python -m venv venv

# Activar entorno virtual (Windows)
venv\Scripts\activate

# Activar entorno virtual (Linux/MacOS)
source venv/bin/activate
```

3. Instalar las dependencias:

```bash
pip install -r requirements.txt
```

## Ejecución

Para ejecutar la aplicación:

```bash
python app.py
```

La aplicación estará disponible en http://127.0.0.1:5000/

## Estructura del Proyecto

```
microservicioAuth/
├── app.py                  # Archivo principal de la aplicación
├── requirements.txt        # Dependencias del proyecto
├── static/                 # Archivos estáticos
│   └── css/
│       └── style.css       # Estilos CSS
├── templates/              # Plantillas HTML
│   ├── base.html           # Plantilla base
│   ├── dashboard.html      # Panel de control del usuario
│   ├── index.html          # Página de inicio
│   ├── login.html          # Página de inicio de sesión
│   └── register.html       # Página de registro
└── venv/                   # Entorno virtual (no incluido en el repositorio)
```

## Base de Datos

La aplicación utiliza SQLite para almacenar datos de usuarios y registros de inicio de sesión. La base de datos se crea automáticamente al iniciar la aplicación por primera vez.

## Seguridad

- Las contraseñas se almacenan utilizando hashing con la biblioteca Werkzeug
- Cada intento de inicio de sesión (exitoso o fallido) se registra con la dirección IP
- Se implementa validación de formularios tanto en el cliente como en el servidor

## Contribución

Si deseas contribuir a este proyecto, ¡no dudes en enviar un pull request!

## Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo LICENSE para obtener más información. 