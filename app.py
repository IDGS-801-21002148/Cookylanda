#---------------------------------IMPORTACIONES ANDREA 
from flask_sqlalchemy import SQLAlchemy  # Añade esta importación
import base64
import traceback # ----Juan
# Hace que PyMySQL imite MySQLdb
import pymysql                    #---ANDREA
pymysql.install_as_MySQLdb()        #----ANDREA

from flask import Flask, render_template, request, redirect, url_for, flash, json, jsonify

from flask_wtf.csrf import CSRFProtect
from config2 import DevelopmentConfig
from models2 import db, Receta, Merma, Producto, Proveedor, Materia, Compra, DetalleCompra, CantidadGalletas, StockGalletas, Venta, DetalleVenta, Galletas, Pedido, DetallePedido
from forms2 import RecetaForm



#-------------------------------------IMPORTACIONES DE XIMENA----------------

from flask import jsonify
import os      # -----------Juan
from sqlalchemy import extract, func  #----Ximena Yolis
import re
from datetime import datetime, timedelta, date
import plotly.express as px #-------Yolanda
import pandas as pd #-------Yolanda
import pyotp
import datetime
import qrcode
from io import BytesIO
from werkzeug.security import generate_password_hash, check_password_hash
from hashlib import sha256
import random

from flask_wtf import FlaskForm 
from flask_wtf import RecaptchaField
import requests
import string
from flask import session
from flask_login import logout_user
from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user
#from flaskext.mysql import MySQL              
from flask_mysqldb import MySQL 
from flask_login import UserMixin
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from flask_sqlalchemy import SQLAlchemy 

#---------------------------IMPORTACIONES DE ROCHA------------------------------------------------------------

from formsRo import TablaProduccion, FormularioRecetas, FormularioMermas  # Importaciones directas
#from modelsRo import db, CantidadGalletas,  Materia, StockGalletas, Merma
from decimal import Decimal, InvalidOperation
from sqlalchemy import exc

#-------------------------------------IMPORTACIONES DE JUAN -----------------------------------------------
from formsJ import CompraForm, ProveedorForm

#-----------------------------------------IMPORTACIONES DE YOLANDA---------------------------------------------
from form import VentaForm, BusquedaForm, MensajeForm, BusquedaPedidosForm, PedidoForm



# -----------------------------------------------CODIGO DE ANDREA GUADALUPE CONCHA DIAZ -----------------------------------



app = Flask(__name__)                #-----ANDREA
app.config.from_object(DevelopmentConfig)  #------ANDREA
csrf = CSRFProtect(app)                   #----------------ANDREA

app.config['SECRET_KEY'] = 'tu_clave_secreta_aqui'  # Clave secreta para CSRF y sesiones
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'alejandro.com13'
app.config['MYSQL_DB'] = 'cookylanda'

mysql = MySQL(app)





csrf.init_app(app)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

app.config["RECAPTCHA_PUBLIC_KEY"] = "6LflK_0qAAAAANxdoeeznqe1Y9eNayGLoNmlnuHK"  # Clave pública
app.config["RECAPTCHA_PRIVATE_KEY"] = "6LflK_0qAAAAAHsp7yEnUhb1S907mA5HtvuFCcGO"  # Clave privada

#csrf = CSRFProtect(app)  # Habilita la protección CSRF
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Ruta a la que redirigir si el usuario no está autenticado



class Usuario(db.Model):
    __tablename__ = 'usuario'

    # Definir la clave primaria y los campos
    idUsuario = db.Column(db.Integer, primary_key=True)
    nombreCompleto = db.Column(db.String(255))
    apePaterno = db.Column(db.String(255))
    apeMaterno = db.Column(db.String(255))
    usuario = db.Column(db.String(255))
    contrasenia = db.Column(db.String(255))
    correo = db.Column(db.String(255))
    rol = db.Column(db.String(50))
    estatus = db.Column(db.String(50))
    codigoUsuario = db.Column(db.String(255))
    
    # Campos adicionales
    intentos_fallidos = db.Column(db.Integer, default=0)
    bloqueado_hasta = db.Column(db.DateTime, nullable=True)
    ultimo_cambio_contrasenia = db.Column(db.DateTime, nullable=True)
    ultimo_inicio_sesion = db.Column(db.DateTime, nullable=True)
    
    # Constructor
    def __init__(self, idUsuario, nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, estatus, codigoUsuario, intentos_fallidos=0, bloqueado_hasta=None, ultimo_cambio_contrasenia=None, ultimo_inicio_sesion=None):
        self.idUsuario = idUsuario
        self.nombreCompleto = nombreCompleto
        self.apePaterno = apePaterno
        self.apeMaterno = apeMaterno
        self.usuario = usuario
        self.contrasenia = contrasenia
        self.correo = correo
        self.rol = rol
        self.estatus = estatus
        self.codigoUsuario = codigoUsuario
        self.intentos_fallidos = intentos_fallidos
        self.bloqueado_hasta = bloqueado_hasta
        self.ultimo_cambio_contrasenia = ultimo_cambio_contrasenia
        self.ultimo_inicio_sesion = ultimo_inicio_sesion




class User(UserMixin):
    def __init__(self, id, usuario, contrasenia, rol, activo=True):  # activo tiene un valor predeterminado
        self.id = id
        self.usuario = usuario
        self.contrasenia = contrasenia
        self.rol = rol
        self._activo = activo  # Atributo privado para almacenar el estado

    @staticmethod
    def get_by_username(db, username):
        cursor = db.connection.cursor()
        cursor.execute("SELECT * FROM usuario WHERE usuario = %s", (username,))
        user_data = cursor.fetchone()
        cursor.close()

        if user_data:
            return User(
                id=user_data[0],  # idUsuario
                usuario=user_data[4],  # usuario
                contrasenia=user_data[5],  # contrasenia
                rol=user_data[7],  # rol
                activo=user_data[8] if len(user_data) > 8 else True  # Campo 'activo' si existe
            )
        return None

class WidgetForm(FlaskForm):
    recaptcha = RecaptchaField()

def validate_recaptcha(response):
    secret_key = app.config["RECAPTCHA_PRIVATE_KEY"]  # Accede a la clave privada desde app.config
    payload = {
        'secret': secret_key,
        'response': response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()
    return result.get('success', False)

def generar_codigo_usuario(rol):
    # Prefijo según el rol
    if rol == 'Administrador':
        prefijo = 'ADM'
    elif rol == 'Cocinero':
        prefijo = 'COC'
    elif rol == 'Vendedor':
        prefijo = 'VEN'
    elif rol == 'Cliente':
        prefijo = 'CLI'
    else:
        prefijo = 'USR'  # Prefijo por defecto

    # Generar un número aleatorio de 4 dígitos
    numero = ''.join(random.choices(string.digits, k=4))

    # Combinar prefijo y número
    return f"{prefijo}-{numero}"

def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.rol not in roles:
                flash("No tienes permisos para acceder a esta página.", "error")
                return redirect(url_for('acceso_denegado'))  # Redirige a 'acceso_denegado'
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/acceso_denegado')
def acceso_denegado():
    return render_template('acceso_denegado.html')

def validar_contraseña(contraseña):
    # Verificar si la contraseña está en la lista de inseguras
    if contraseña in CONTRASEÑAS_INSEGURAS:
        return "Esta contraseña es muy común y no es segura. Por favor elige otra."
    
    # Validaciones originales (mantén las que ya tienes)
    if len(contraseña) < 8:
        return "La contraseña debe tener al menos 8 caracteres."
    if not re.search(r"[A-Z]", contraseña):
        return "La contraseña debe contener al menos una letra mayúscula."
    if not re.search(r"[a-z]", contraseña):
        return "La contraseña debe contener al menos una letra minúscula."
    if not re.search(r"[0-9]", contraseña):
        return "La contraseña debe contener al menos un número."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", contraseña):
        return "La contraseña debe contener al menos un carácter especial."
    
    return None

@app.before_request
def clear_session():
    global session_cleared
    if not session_cleared:
        session.clear()
        logout_user()
        session_cleared = True

@login_manager.user_loader
def load_user(id):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM usuario WHERE idUsuario = %s", (id,))
    user_data = cursor.fetchone()
    cursor.close()

    if user_data:
        return User(
            id=user_data[0],  # idUsuario
            usuario=user_data[4],  # usuario
            contrasenia=user_data[5],  # contrasenia
            rol=user_data[7],  # rol
            activo=user_data[8] if len(user_data) > 8 else True  # Campo 'activo' si existe
        )
    return None

@app.route('/')
def index():
    return render_template('index.html')  # Renderiza la página principal directamente
session_cleared = False

# Remove or modify this function
@app.before_request
def before_request():
    if current_user.is_authenticated:
        # Renovar la sesión
        session.permanent = True
        app.permanent_session_lifetime = timedelta(minutes=40)
        session.modified = True

# Definir rutas después de que 'app' esté definido
from datetime import datetime, timedelta



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Obtener la respuesta del CAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')

        # Validar el CAPTCHA
        if not validate_recaptcha(recaptcha_response):
            flash("Por favor, completa el CAPTCHA.", "error")
            return redirect(url_for('login'))

        # Obtener datos del formulario
        usuario = request.form.get('usuario')
        contrasenia = request.form.get('contrasenia')

        if not usuario or not contrasenia:
            flash("Por favor, rellena todos los campos.", "error")
            return redirect(url_for('login'))

        # Verificar si el usuario está bloqueado
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT bloqueado_hasta FROM usuario WHERE usuario = %s", (usuario,))
        bloqueado_hasta = cursor.fetchone()

        if bloqueado_hasta and bloqueado_hasta[0] and datetime.now() < bloqueado_hasta[0]:
            flash("Tu cuenta está bloqueada temporalmente. Inténtalo más tarde.", "error")
            return redirect(url_for('login'))

        # Verificar el usuario y la contraseña
        cursor.execute("SELECT * FROM usuario WHERE usuario = %s", (usuario,))
        user_data = cursor.fetchone()

        if user_data:
            if check_password_hash(user_data[5], contrasenia):  # Índice 5 es la contraseña
                # Reiniciar intentos fallidos
                cursor.execute("UPDATE usuario SET intentos_fallidos = 0 WHERE usuario = %s", (usuario,))
                
                # Registrar el último inicio de sesión
                cursor.execute("UPDATE usuario SET ultimo_inicio_sesion = %s WHERE usuario = %s", (datetime.now(), usuario))
                mysql.connection.commit()

                # Verificar si necesita cambiar la contraseña
                cursor.execute("SELECT ultimo_cambio_contrasenia FROM usuario WHERE usuario = %s", (usuario,))
                ultimo_cambio = cursor.fetchone()[0]

                if datetime.now() - ultimo_cambio > timedelta(days=90):  # Cambiar cada 90 días
                    flash("Debes cambiar tu contraseña. Ha pasado más de 90 días desde el último cambio.", "warning")
                    return redirect(url_for('cambiar_contrasenia'))  # Redirigir a la página de cambio de contraseña

                # Iniciar sesión
                user = User(user_data[0], user_data[4], user_data[5], user_data[7])
                login_user(user)

                # Redirigir según el rol
                if user.rol == 'Cliente':
                    return redirect(url_for('catalogo'))
                elif user.rol == 'Administrador':
                    return redirect(url_for('admin'))
                elif user.rol == 'Cocinero':
                    return redirect(url_for('recetas'))
                elif user.rol == 'Vendedor':
                    return redirect(url_for('vendedor'))
                else:
                    return redirect(url_for('index'))
            else:
                # Incrementar intentos fallidos
                cursor.execute("UPDATE usuario SET intentos_fallidos = intentos_fallidos + 1 WHERE usuario = %s", (usuario,))
                mysql.connection.commit()

                # Verificar si superó los 3 intentos
                cursor.execute("SELECT intentos_fallidos FROM usuario WHERE usuario = %s", (usuario,))
                intentos_fallidos = cursor.fetchone()[0]

                if intentos_fallidos >= 3:
                    # Bloquear al usuario por 5 minutos
                    bloqueado_hasta = datetime.now() + timedelta(minutes=5)
                    cursor.execute("UPDATE usuario SET bloqueado_hasta = %s WHERE usuario = %s", (bloqueado_hasta, usuario))
                    mysql.connection.commit()
                    flash("Has excedido el número de intentos. Tu cuenta está bloqueada por 5 minutos.", "error")
                else:
                    flash(f"Contraseña incorrecta. Te quedan {3 - intentos_fallidos} intentos.", "error")
                return redirect(url_for('login'))
        else:
            flash("Usuario no encontrado.", "error")
            return redirect(url_for('login'))

    return render_template('auth/login.html', recaptcha_public_key=app.config['RECAPTCHA_PUBLIC_KEY'])

from flask_login import logout_user

@app.route('/logout')
@login_required
def logout():
    logout_user()  # Cierra la sesión del usuario
    flash("Has cerrado sesión correctamente.", "success")
    return redirect(url_for('login'))  # Redirige al login

@app.route('/vendedor')
@login_required
@roles_required('Vendedor', "Administrador")  # Solo usuarios con rol 'Vendedor' pueden acceder
def vendedor(): 
    return render_template('ventasIndex.html')  # Renderiza el template vendedor.html

@app.route('/recetas')
@login_required
@roles_required('Cocinero', 'Administrador')
def recetas():

    # Obtener todos los registros de stock de galletas
    stock_galletas = StockGalletas.query.order_by(StockGalletas.nombreGalleta).all()
    
    # Calcular días restantes hasta caducidad
    hoy = date.today()
    for galleta in stock_galletas:
        dias_restantes = (galleta.fechaPreparacion + timedelta(days=14) - hoy).days
        galleta.dias_restantes = max(0, dias_restantes)  # No mostrar números negativos
    return render_template('principalA.html', stock_galletas=stock_galletas)     #----------------------------------CAMBIE AQUI ANDREA 
    

@app.route('/a')
@login_required
@roles_required('Administrador')
def ad():
    return render_template('principalAdmin.html')   #----------------------------------CAMBIE AQUI ANDREA 






@app.route('/cambiar_contrasenia', methods=['GET', 'POST'])
@login_required
def cambiar_contrasenia():
    if request.method == 'POST':
        contrasenia_actual = request.form.get('contrasenia_actual')
        nueva_contrasenia = request.form.get('nueva_contrasenia')
        confirmar_contrasenia = request.form.get('confirmar_contrasenia')

        # Verificar la contraseña actual
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT contrasenia FROM usuario WHERE idUsuario = %s", (current_user.id,))
        contrasenia_hash = cursor.fetchone()[0]

        if not check_password_hash(contrasenia_hash, contrasenia_actual):
            flash("La contraseña actual es incorrecta.", "error")
            return redirect(url_for('cambiar_contrasenia'))

        # Validar la nueva contraseña
        if nueva_contrasenia != confirmar_contrasenia:
            flash("Las contraseñas no coinciden.", "error")
            return redirect(url_for('cambiar_contrasenia'))

        mensaje_error = validar_contraseña(nueva_contrasenia)
        if mensaje_error:
            flash(mensaje_error, "error")
            return redirect(url_for('cambiar_contrasenia'))

        # Actualizar la contraseña
        nueva_contrasenia_hash = generate_password_hash(nueva_contrasenia)
        cursor.execute(
            "UPDATE usuario SET contrasenia = %s, ultimo_cambio_contrasenia = %s WHERE idUsuario = %s",
            (nueva_contrasenia_hash, datetime.now(), current_user.id)
        )
        mysql.connection.commit()
        flash("Contraseña cambiada exitosamente.", "success")
        return redirect(url_for('ventas'))  # Redirigir al dashboard

    return render_template('auth/cambiar_contrasenia.html')




@app.route('/catalogo')
@login_required
@roles_required('Cliente')
def catalogo():
    return render_template('principlaYolis.html')




@app.route('/admin', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador')
def admin():
    cursor = mysql.connection.cursor() # Abrir cursor al inicio de la función

    if request.method == 'POST':
        # --- CREAR USUARIO ---
        nombreCompleto = request.form.get('nombreCompleto', '').strip()
        apePaterno = request.form.get('apePaterno', '').strip()
        apeMaterno = request.form.get('apeMaterno', '').strip()
        usuario_form = request.form.get('usuario', '').strip() # Renombrar para evitar conflicto
        contrasenia_plain = request.form.get('contrasenia', '').strip()
        correo = request.form.get('correo', '').strip()
        rol = request.form.get('rol', '').strip()

        # Validaciones básicas (puedes añadir más)
        if not all([nombreCompleto, apePaterno, apeMaterno, usuario_form, contrasenia_plain, correo, rol]):
            flash("Todos los campos son requeridos.", "error")
            # Obtener usuarios para mostrar la tabla incluso si hay error en POST
            cursor.execute("SELECT * FROM usuario ORDER BY idUsuario DESC")
            usuarios_tuplas = cursor.fetchall()
            cursor.close()
            usuarios = _mapear_usuarios(usuarios_tuplas)
            return render_template('admin.html', usuarios=usuarios)

        mensaje_error_pass = validar_contraseña(contrasenia_plain)
        if mensaje_error_pass:
             flash(mensaje_error_pass, "error")
             cursor.execute("SELECT * FROM usuario ORDER BY idUsuario DESC")
             usuarios_tuplas = cursor.fetchall()
             cursor.close()
             usuarios = _mapear_usuarios(usuarios_tuplas)
             return render_template('admin.html', usuarios=usuarios)

        # Verificar si usuario o correo ya existen
        cursor.execute("SELECT idUsuario FROM usuario WHERE usuario = %s", (usuario_form,))
        if cursor.fetchone():
            flash(f"El nombre de usuario '{usuario_form}' ya está en uso.", "error")
            cursor.execute("SELECT * FROM usuario ORDER BY idUsuario DESC")
            usuarios_tuplas = cursor.fetchall()
            cursor.close()
            usuarios = _mapear_usuarios(usuarios_tuplas)
            return render_template('admin.html', usuarios=usuarios)

        cursor.execute("SELECT idUsuario FROM usuario WHERE correo = %s", (correo,))
        if cursor.fetchone():
            flash(f"El correo electrónico '{correo}' ya está registrado.", "error")
            cursor.execute("SELECT * FROM usuario ORDER BY idUsuario DESC")
            usuarios_tuplas = cursor.fetchall()
            cursor.close()
            usuarios = _mapear_usuarios(usuarios_tuplas)
            return render_template('admin.html', usuarios=usuarios)

        # Hashear contraseña y generar código
        contrasenia_hash = generate_password_hash(contrasenia_plain)
        codigoUsuario = generar_codigo_usuario(rol)
        estatus = 'Activo' # Estado inicial
        ahora = datetime.now() # Fecha/hora actual

        try:
            cursor.execute(
                """INSERT INTO usuario
                   (nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, estatus, codigoUsuario, ultimo_cambio_contrasenia)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (nombreCompleto, apePaterno, apeMaterno, usuario_form, contrasenia_hash, correo, rol, estatus, codigoUsuario, ahora)
            )
            mysql.connection.commit()
            flash("Usuario creado exitosamente.", "success")
        except Exception as e:
            mysql.connection.rollback()
            flash(f"Error al crear el usuario: {str(e)}", "error")
            app.logger.error(f"Error DB al crear usuario: {e}") # Log del error
        finally:
            # No cerrar el cursor aquí si lo necesitamos para el GET
            pass # Se cerrará al final del bloque GET

        return redirect(url_for('admin'))  # Redirigir siempre después de POST exitoso

    # --- OBTENER USUARIOS (GET) ---
    try:
        cursor.execute("SELECT * FROM usuario ORDER BY idUsuario DESC") # Ordenar por ID descendente
        usuarios_tuplas = cursor.fetchall()
        usuarios = _mapear_usuarios(usuarios_tuplas) # Usar función helper
    except Exception as e:
        flash(f"Error al cargar usuarios: {str(e)}", "error")
        app.logger.error(f"Error DB al obtener usuarios: {e}") # Log del error
        usuarios = []
    finally:
        cursor.close() # Cerrar cursor después de usarlo

    return render_template('admin.html', usuarios=usuarios)

# Función helper para mapear tuplas a objetos Usuario (si decides usar el objeto)
# O simplemente para devolver diccionarios si prefieres
def _mapear_usuarios(usuarios_tuplas):
    usuarios = []
    if usuarios_tuplas:
        for u in usuarios_tuplas:
            # Opción 1: Crear objeto Usuario (asegúrate que coincida con _init_)
            # usuario_obj = Usuario(
            #     idUsuario=u[0], nombreCompleto=u[1], apePaterno=u[2], apeMaterno=u[3],
            #     usuario=u[4], contrasenia=u[5], correo=u[6], rol=u[7], estatus=u[8],
            #     codigoUsuario=u[9], intentos_fallidos=u[10], bloqueado_hasta=u[11],
            #     ultimo_cambio_contrasenia=u[12], ultimo_inicio_sesion=u[13]
            # )
            # usuarios.append(usuario_obj)

            # Opción 2: Devolver diccionarios (más simple si no necesitas métodos del objeto)
             usuarios.append({
                 'idUsuario': u[0], 'nombreCompleto': u[1], 'apePaterno': u[2], 'apeMaterno': u[3],
                 'usuario': u[4], 'correo': u[6], 'rol': u[7], 'estatus': u[8],
                 'codigoUsuario': u[9]
                 # No incluir contraseña hash en lo que se pasa a la plantilla
             })
    return usuarios





@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador')
def editar_usuario(id):
    cursor = None # Inicializar cursor a None
    try:
        # Usar DictCursor para fácil acceso a los datos por nombre de columna
        cursor = mysql.connection.cursor(pymysql.cursors.DictCursor)

        # Primero, obtener los datos actuales del usuario SIEMPRE, tanto para GET como para POST (antes de validar)
        cursor.execute("SELECT * FROM usuario WHERE idUsuario = %s", (id,))
        usuario_data = cursor.fetchone()

        # Si el usuario no existe (ni para GET ni para POST)
        if not usuario_data:
            flash("Usuario no encontrado.", "error")
            # No hay cursor que cerrar aquí si fetchone falla inicialmente, pero por si acaso
            if cursor and cursor.connection and not getattr(cursor, 'closed', True): cursor.close()
            return redirect(url_for('admin'))

        # --- Lógica para POST (Actualizar) ---
        if request.method == 'POST':
            nombreCompleto = request.form.get('nombreCompleto', '').strip()
            apePaterno = request.form.get('apePaterno', '').strip()
            apeMaterno = request.form.get('apeMaterno', '').strip()
            usuario_form = request.form.get('usuario', '').strip()
            correo = request.form.get('correo', '').strip()
            nuevo_rol = request.form.get('rol', '').strip()
            estatus = request.form.get('estatus', 'Activo').strip()

            # Validaciones básicas
            if not all([nombreCompleto, apePaterno, apeMaterno, usuario_form, correo, nuevo_rol, estatus]):
                flash("Todos los campos son requeridos.", "error")
                # Ya tenemos usuario_data, simplemente renderizamos la plantilla de nuevo
                return render_template('editar_usuario.html', usuario=usuario_data)

            # Verificar si el nuevo usuario o correo (si cambiaron) ya existen en OTRO usuario
            cursor.execute("SELECT idUsuario FROM usuario WHERE usuario = %s AND idUsuario != %s", (usuario_form, id))
            if cursor.fetchone():
                flash(f"El nombre de usuario '{usuario_form}' ya está en uso por otro usuario.", "error")
                return render_template('editar_usuario.html', usuario=usuario_data)

            cursor.execute("SELECT idUsuario FROM usuario WHERE correo = %s AND idUsuario != %s", (correo, id))
            if cursor.fetchone():
                flash(f"El correo electrónico '{correo}' ya está registrado por otro usuario.", "error")
                return render_template('editar_usuario.html', usuario=usuario_data)

            # --- Lógica para actualizar codigoUsuario ---
            original_rol = usuario_data['rol'] # Usamos los datos ya cargados
            original_codigo = usuario_data['codigoUsuario']
            codigo_final_usuario = original_codigo

            if nuevo_rol != original_rol:
                print(f"Detectado cambio de rol para ID {id}: de '{original_rol}' a '{nuevo_rol}'")
                if nuevo_rol in ['Administrador', 'Cocinero', 'Vendedor']:
                    codigo_final_usuario = generar_codigo_usuario(nuevo_rol)
                    print(f"Nuevo código generado: {codigo_final_usuario}")
                else:
                    codigo_final_usuario = None
                    print("Nuevo rol no requiere código, estableciendo a NULL.")
            # --- Fin Lógica codigoUsuario ---

            # Intentar la actualización
            try:
                cursor.execute(
                    """UPDATE usuario SET
                       nombreCompleto = %s, apePaterno = %s, apeMaterno = %s,
                       usuario = %s, correo = %s, rol = %s, estatus = %s,
                       codigoUsuario = %s
                       WHERE idUsuario = %s""",
                    (nombreCompleto, apePaterno, apeMaterno, usuario_form, correo, nuevo_rol, estatus,
                     codigo_final_usuario, id)
                )
                mysql.connection.commit()
                flash("Usuario actualizado exitosamente.", "success")
                # Cerrar cursor y redirigir DESPUÉS del commit exitoso
                if cursor and cursor.connection and not getattr(cursor, 'closed', True): cursor.close()
                return redirect(url_for('admin'))

            except pymysql.err.IntegrityError as ie:
                mysql.connection.rollback()
                if "Duplicate entry" in str(ie) and "codigoUsuario" in str(ie):
                    flash(f"Error: El código de usuario generado ('{codigo_final_usuario}') ya existe. Intenta guardar de nuevo.", "error")
                    app.logger.error(f"Error de integridad (codigoUsuario duplicado?) al editar usuario {id}: {ie}")
                else:
                    flash(f"Error de base de datos al actualizar: {str(ie)}", "error")
                    app.logger.error(f"Error DB Integrity al editar usuario {id}: {ie}")
                # Renderizar de nuevo el formulario con el error
                return render_template('editar_usuario.html', usuario=usuario_data)

            except Exception as e:
                mysql.connection.rollback()
                flash(f"Error inesperado al actualizar el usuario: {str(e)}", "error")
                app.logger.error(f"Error inesperado al editar usuario {id}: {e}")
                # Renderizar de nuevo el formulario con el error
                return render_template('editar_usuario.html', usuario=usuario_data)

        # --- Lógica para GET (Mostrar Formulario) ---
        else: # request.method == 'GET'
            # Ya tenemos usuario_data cargado al principio
            return render_template('editar_usuario.html', usuario=usuario_data)

    except Exception as e:
        # Captura errores generales (ej: error de conexión)
        flash(f"Error general en la operación de edición: {str(e)}", "error")
        app.logger.error(f"Error general en editar_usuario (ID: {id}): {e}")
        # Asegurarse de cerrar el cursor si se abrió
        if cursor and cursor.connection and not getattr(cursor, 'closed', True): cursor.close()
        return redirect(url_for('admin')) # Redirigir en caso de error grave

    finally:
        # Asegurarse de que el cursor SIEMPRE se cierre si se abrió y no se cerró antes
        if cursor and cursor.connection and not getattr(cursor, 'closed', True):
            print(f"Cerrando cursor en finally para ID {id}") # Debug
            cursor.close()





@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        # Verificar si el usuario ya completó el formulario y está en la fase de validación del token
        if 'secret' in session and 'token' in request.form:
            # Validar el token proporcionado por el usuario
            secret = session['secret']
            token = request.form['token']

            # Verificar el token
            totp = pyotp.TOTP(secret)
            if totp.verify(token):
                # Token válido, completar el registro
                nombreCompleto = session['nombreCompleto']
                apePaterno = session['apePaterno']
                apeMaterno = session['apeMaterno']
                usuario = session['usuario']
                contrasenia = session['contrasenia']
                correo = session['correo']
                rol = session['rol']

                # Insertar el nuevo usuario en la base de datos
                cursor = mysql.connection.cursor()
                try:
                    cursor.execute(
                        "INSERT INTO usuario (nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, codigoUsuario) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, generar_codigo_usuario(rol))
                    )
                    mysql.connection.commit()
                    flash("Usuario registrado exitosamente.", "success")
                    # Limpiar la sesión
                    session.pop('nombreCompleto', None)
                    session.pop('apePaterno', None)
                    session.pop('apeMaterno', None)
                    session.pop('usuario', None)
                    session.pop('contrasenia', None)
                    session.pop('correo', None)
                    session.pop('rol', None)
                    session.pop('secret', None)
                    return redirect(url_for('login'))
                except Exception as e:
                    mysql.connection.rollback()
                    flash(f"Error al registrar el usuario: {str(e)}", "error")
                    return redirect(url_for('registro'))
                finally:
                    cursor.close()
            else:
                flash("Token inválido. Inténtalo de nuevo.", "error")
                return redirect(url_for('registro'))

        # Si no es la fase de validación del token, procesar el formulario inicial
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not validate_recaptcha(recaptcha_response):
            flash('Por favor, completa el CAPTCHA.', 'error')
            return redirect(url_for('registro'))

        # Obtener datos del formulario
        nombreCompleto = request.form.get('nombreCompleto')
        apePaterno = request.form.get('apePaterno')
        apeMaterno = request.form.get('apeMaterno')
        usuario = request.form.get('usuario')
        contrasenia = request.form.get('contrasenia')
        correo = request.form.get('correo')
        rol = 'Cliente'  # Rol por defecto

        # Validar los datos del formulario
        if not re.match(r"^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]{2,}$", nombreCompleto):
            flash("El nombre completo debe contener solo letras y espacios, y tener al menos 2 caracteres.", "error")
            return redirect(url_for('registro'))

        if not re.match(r"^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]{2,}$", apePaterno):
            flash("El apellido paterno debe contener solo letras y espacios, y tener al menos 2 caracteres.", "error")
            return redirect(url_for('registro'))

        if not re.match(r"^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]{2,}$", apeMaterno):
            flash("El apellido materno debe contener solo letras y espacios, y tener al menos 2 caracteres.", "error")
            return redirect(url_for('registro'))

        if not re.match(r"^[a-zA-Z0-9_]{5,20}$", usuario):
            flash("El usuario debe tener entre 5 y 20 caracteres y solo puede contener letras, números y guiones bajos.", "error")
            return redirect(url_for('registro'))

        # Verificar si el usuario ya existe
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM usuario WHERE usuario = %s", (usuario,))
        if cursor.fetchone():
            flash("El nombre de usuario ya está en uso.", "error")
            cursor.close()
            return redirect(url_for('registro'))

        # Validar la contraseña
        mensaje_error = validar_contraseña(contrasenia)
        if mensaje_error:
            flash(mensaje_error, "error")
            return redirect(url_for('registro'))

        # Hash de la contraseña
        contrasenia_hash = generate_password_hash(contrasenia)

        # Guardar los datos en la sesión para usarlos después de la validación del token
        session['nombreCompleto'] = nombreCompleto
        session['apePaterno'] = apePaterno
        session['apeMaterno'] = apeMaterno
        session['usuario'] = usuario
        session['contrasenia'] = contrasenia_hash
        session['correo'] = correo
        session['rol'] = rol

        # Generar un secreto para el usuario
        secret = pyotp.random_base32()
        session['secret'] = secret

        # Generar la URL para el código QR
        provisioning_url = pyotp.totp.TOTP(secret).provisioning_uri(name=usuario, issuer_name="TuAplicación")

        # Generar el código QR
        img = qrcode.make(provisioning_url)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        # Mostrar la página de validación del token
        return render_template('auth/validar_token.html', qr_code=img_str)

    # Si el método es GET, mostrar el formulario de registro
    return render_template('auth/registro.html', recaptcha_public_key=app.config['RECAPTCHA_PUBLIC_KEY'])

@app.route('/administrador')
@login_required
@roles_required('Administrador')
def administrador():
    cursor = mysql.connection.cursor()
    # Seleccionamos solo los campos necesarios
    cursor.execute("SELECT idUsuario, nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, estatus, codigoUsuario FROM usuario")
    usuarios_tuplas = cursor.fetchall()
    cursor.close()

    # En lugar de crear objetos Usuario desde las tuplas, pasamos directamente los valores a la clase
    usuarios = []
    for usuario in usuarios_tuplas:
        # Extraemos cada campo individualmente
        idUsuario, nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, estatus, codigoUsuario = usuario
        # Creamos el objeto Usuario
        usuario_obj = Usuario(idUsuario, nombreCompleto, apePaterno, apeMaterno, usuario, contrasenia, correo, rol, estatus, codigoUsuario)
        usuarios.append(usuario_obj)

    return render_template('administrador.html', usuarios=usuarios)



@app.route('/eliminar_usuario/<int:id>', methods=['POST'])
@login_required
@roles_required('Administrador') # Asegurar rol aquí también
def eliminar_usuario(id):
    # Impedir que el administrador se elimine a sí mismo
    if id == current_user.id:
        flash("No puedes eliminar tu propia cuenta de administrador.", "error")
        return redirect(url_for('admin'))

    cursor = mysql.connection.cursor()
    try:
        # Verificar si el usuario existe antes de intentar eliminar
        cursor.execute("SELECT idUsuario FROM usuario WHERE idUsuario = %s", (id,))
        if cursor.fetchone():
            cursor.execute("DELETE FROM usuario WHERE idUsuario = %s", (id,))
            mysql.connection.commit()
            flash("Usuario eliminado exitosamente.", "success")
        else:
            flash("El usuario que intentas eliminar no existe.", "warning")

    except Exception as e:
        mysql.connection.rollback()
        # Podría fallar por restricciones de clave foránea si el usuario tiene registros asociados
        flash(f"Error al eliminar el usuario: {str(e)}. Verifica si tiene registros asociados.", "error")
        app.logger.error(f"Error DB al eliminar usuario {id}: {e}")
    finally:
        cursor.close()

    return redirect(url_for('admin')) # Redirigir al panel principal


# Cargar contraseñas inseguras
def cargar_contraseñas_inseguras():
    try:
        with open('data/2020-200_most_used_passwords.txt', 'r') as f:
            return {line.strip() for line in f}
    except FileNotFoundError:
        print("¡Advertencia! No se encontró el archivo de contraseñas inseguras")
        return set()

CONTRASEÑAS_INSEGURAS = cargar_contraseñas_inseguras()


#----------------------------------------------------------------------------------------------

#----------------------------------------CODIGO DE ROCHA-------------------------------------------------------

# Nueva ruta para obtener stock de materia prima
@app.route("/get_stock_materia/<int:id_producto>")
@login_required
@roles_required('Cocinero', 'Administrador')
def get_stock_materia(id_producto):
    materia = Materia.query.get_or_404(id_producto)
    return jsonify({
        'cantidad': float(materia.cantidad),
        'tipo': 'materia'  # Agregamos tipo para validación
    })

# Nueva ruta para obtener stock de galletas
@app.route("/get_stock_galleta/<int:id_stock>")
@login_required
@roles_required('Cocinero', 'Administrador') 
def get_stock_galleta(id_stock):
    galleta = StockGalletas.query.get_or_404(id_stock)
    return jsonify({
        'cantidad': float(galleta.cantidadPiezas),
        'tipo': 'galleta'  # Agregamos tipo para validación
    })


@app.route("/mermas", methods=["GET", "POST"])
@login_required
@roles_required('Cocinero', 'Administrator') 
def mermas():
    if 'user' not in session:
        session['user'] = 'default_user'

    form = FormularioMermas()
    
    try:
        # Obtener productos con stock
        materias = Materia.query.filter(Materia.cantidad > 0).all()
        galletas = StockGalletas.query.filter(StockGalletas.cantidadPiezas > 0).all()
        
        # Configurar opciones del formulario
        form.tipoMerma.choices = [
            ("Caducidad Materia Prima", "Caducidad Materia Prima"),
            ("Caducidad Galletas", "Caducidad Galletas"),
            ("Quemado", "Quemado"),
            ("Galletas rotas", "Galletas rotas"),
            ("Pérdidas por manipulación", "Pérdidas por manipulación")
        ]
        
        form.lote.choices = [("", "Seleccione...")] + [
            (f"materia_{m.idProducto}", f"{m.nombreProducto} (ID: {m.idProducto})") 
            for m in materias
        ] + [
            (f"galleta_{g.idStock}", f"{g.nombreGalleta} (Lote: {g.idStock})") 
            for g in galletas
        ]

        if request.method == "POST" and form.validate_on_submit():
            # Validar que se haya seleccionado un lote
            if not form.lote.data or form.lote.data == "":
                flash("Debe seleccionar un lote válido", "danger")
                return redirect(url_for("mermas"))
            
            tipo_merma = form.tipoMerma.data
            lote_seleccionado = form.lote.data
            cantidad_str = form.cantidadMerma.data
            fecha = form.fechaMerma.data or datetime.now().date()
            
            # Convertir la cantidad a Decimal de manera segura
            try:
                cantidad = Decimal(str(cantidad_str))
            except:
                flash("Cantidad inválida", "danger")
                return redirect(url_for("mermas"))
            
            producto_nombre = ""
            error_ocurrido = False
            
            # Procesar MATERIA PRIMA
            if lote_seleccionado.startswith("materia_"):
                id_producto = int(lote_seleccionado.split("_")[1])
                materia = Materia.query.get(id_producto)
                
                if materia:
                    cantidad_materia = Decimal(str(materia.cantidad))
                    if cantidad_materia >= cantidad:
                        materia.cantidad = float(cantidad_materia - cantidad)
                        producto_nombre = materia.nombreProducto
                    else:
                        flash("La cantidad excede el stock disponible de materia prima", "danger")
                        error_ocurrido = True
                else:
                    flash("Materia prima no encontrada", "danger")
                    error_ocurrido = True
            
            # Procesar GALLETAS
            elif lote_seleccionado.startswith("galleta_"):
                id_stock = int(lote_seleccionado.split("_")[1])
                galleta = db.session.get(StockGalletas, id_stock)
                
                if galleta:
                    cantidad_galletas = Decimal(str(galleta.cantidadPiezas))
                    if cantidad_galletas >= cantidad:
                        cantidad_str = str(cantidad)
                        if '.' in cantidad_str:
                            decimal_part = cantidad_str.split('.')[1]
                            if decimal_part != '00' and decimal_part != '0':
                                flash("Para galletas debe ingresar valores enteros (ej. 10 o 10.00)", "danger")
                                error_ocurrido = True
                            else:
                                galleta.cantidadPiezas = int(float(cantidad_galletas - cantidad))
                                producto_nombre = galleta.nombreGalleta
                        else:
                            galleta.cantidadPiezas = int(float(cantidad_galletas - cantidad))
                            producto_nombre = galleta.nombreGalleta
                    else:
                        flash("La cantidad excede el stock disponible de galletas", "danger")
                        error_ocurrido = True
                else:
                    flash("Galleta no encontrada", "danger")
                    error_ocurrido = True
            else:
                flash("Tipo de lote no reconocido", "danger")
                error_ocurrido = True

            # Registrar merma si todo es válido
            if not error_ocurrido and producto_nombre:
                nueva_merma = Merma(
                    tipoMerma=tipo_merma,
                    lote=lote_seleccionado,
                    producto=producto_nombre,
                    cantidadMerma=float(cantidad),
                    fechaMerma=fecha,
                    codigoUsuario=session['user']
                )
                
                db.session.add(nueva_merma)
                db.session.commit()
                flash("Merma registrada correctamente", "success")
            
            return redirect(url_for("mermas"))

        # Obtener historial de mermas ordenado por ID descendente
        historial = Merma.query.order_by(Merma.idMerma.desc()).all()
        
    except Exception as e:
        flash(f"Error en la aplicación: {str(e)}", "danger")
        db.session.rollback()
        historial = []
    
    return render_template("mermas.html", form=form, historial_mermas=historial)

#----------------ANDREA---------------------------------


@app.route('/ahYhhja')
@login_required 
@roles_required('Cocinero', 'Administrador')
def catalogoReceta():
    recetas = Receta.query.filter_by(estatus='Activo').all() # Obtener todas las recetas de la base de datos
    return render_template('catalogoReceta.html', recetas=recetas)

@app.route('/v/<int:id>')
@login_required 
@roles_required('Cocinero', 'Administrador')
def verReceta(id):
    receta = Receta.query.get_or_404(id)  # Obtener la receta específica o mostrar error 404
    return render_template('verReceta.html', receta=receta)

@app.route('/jdhhdA')
@login_required 
@roles_required('Cocinero', 'Administrador')
def home():
    return render_template('principalA.html') 






@app.route('/ujhjsbx', methods=['GET', 'POST'])
@login_required 
@roles_required('Cocinero', 'Administrador')
def registro_receta():

    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    def allowed_file(filename):
        return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


    form = RecetaForm()

    recetas = Receta.query.all()  # Consulta las recetas desde la base de datos
    print("Recetas obtenidas:", recetas)  # Esto imprimirá los registros en la consola


    if request.method == 'POST':

        print("Datos del formulario recibidos:")
        print(request.form)  # Esto imprimirá los datos en la consola


        codigoUsuario = request.form.get('codigoUsuario')

        # Ejecutar consulta SQL directa usando flask_mysqldb
        cursor = mysql.connection.cursor()
        cursor.execute(
            "SELECT codigoUsuario, rol FROM usuario WHERE codigoUsuario = %s AND rol = 'Cocinero'",
            (codigoUsuario,)
        )
        usuario_data = cursor.fetchone()
        cursor.close()

        # Verificar si se encontró el usuario
        if not usuario_data:
            flash("Error: Código de usuario no válido o no es Cocinero", "danger")
            return redirect(url_for('registro_receta'))

        # Crear instancia de la clase Usuario de Ximena (si es necesario)
        usuario = Usuario(
            idUsuario=None,  # No es necesario para esta validación
            nombreCompleto="",
            apePaterno="",
            apeMaterno="",
            usuario="",
            contrasenia="",
            correo="",
            rol=usuario_data[1],  # Obtener el rol desde la consulta
            estatus="",
            codigoUsuario=usuario_data[0]  # Obtener el código desde la consulta
        )



        if form.validate():
            print("Formulario validado correctamente")

            # En tu ruta donde procesas el formulario:
            imagen = request.files.get('imagen')

            if imagen and imagen.filename != '':  # Verifica si hay una imagen seleccionada
                if not allowed_file(imagen.filename):
                    flash("Formato de imagen no válido. Solo se permiten PNG, JPG y JPEG", "danger")
                    return render_template('registroReceta.html', form=form, recetas=recetas)

                try:
                    imagen_bin = imagen.read()
                    imagen_base64 = base64.b64encode(imagen_bin).decode('utf-8')  # Convertir a base64
                except Exception as e:
                    flash(f"Error al procesar la imagen: {str(e)}", "danger")
                    return render_template('registroReceta.html', form=form, recetas=recetas)
            else:
                imagen_base64 = None  # Si no se subió imagen, almacena None

            
            # Procesar ingredientes adicionales
            adicionales = request.form.getlist('adicional')
            cant_adicionales = request.form.getlist('cantAdicional')
            unidades = request.form.getlist('unidad')
            # Validar y filtrar
            ingredientes_validos = []
            for a, c, u in zip(adicionales, cant_adicionales, unidades):
                a = a.strip()
                c = c.strip().replace("'", "").replace(",", ".")  # Limpiar formato numérico
                u = u.strip()
                # Validación estricta
                
                if a and c and u:
                    try:
                        # Convertir cantidad a float
                        float(c)
                        ingredientes_validos.append((a, c, u))
                    except ValueError:
                        flash(f"Valor numérico inválido en cantidad: {c}", "danger")
                        
            # Actualizar listas
            lista_adicionales = [ing[0] for ing in ingredientes_validos]
            lista_cantidades = [ing[1] for ing in ingredientes_validos]
            lista_unidades = [ing[2] for ing in ingredientes_validos]
            

            nueva_receta = Receta(
                nombreGalleta=form.nombreGalleta.data,

                harIng=form.cmbHarina.data,
                cantHar=form.cantHar.data,
                harUdad=form.cmbHarinaUnidad.data,

                manIng=form.cmbMantequilla.data,
                cantMan=form.cantMan.data,
                manUdad=form.cmbMantUnidad.data,

                azurIng=form.cmbAzucar.data,
                cantAzur=form.cantAzur.data,
                azurUdad=form.cmbAzurUnidad.data,

                huvrIng=form.cmbHuevo.data,
                cantHuv=form.cantHuv.data,
                huvUdad=form.cmbHuevUnidad.data,

                horIng=form.cmbPolvo.data,
                cantHor=form.cantHor.data,
                horUdad=form.cmbPolvoUnidad.data,

                salIng=form.cmbSal.data,
                cantSal=form.cantSal.data,
                salUdad=form.cmbSalUnidad.data,

                LechIng=form.cmbLe.data,
                cantLech=form.cantLech.data,
                lechUdad=form.cmbLecheUnidad.data,

                adicional=lista_adicionales,
                cantAdicional=lista_cantidades,
                unidad=lista_unidades,

                procedimiento=form.procedimiento.data,
                estatus=form.estatus.data,
                codigoUsuario=form.codigoUsuario.data,
                imagen=imagen_base64 
            )

            try:
                # Guardar la receta
                db.session.add(nueva_receta)
                db.session.flush()  # Para obtener el ID de la receta recién insertada

                # Crear la galleta asociada
                nueva_galleta = Galletas(
                    nombre=form.nombreGalleta.data,
                    descripcion=f"Receta de {form.nombreGalleta.data}",
                    precioUnitario=float(form.precioUnitario.data)
                )
                db.session.add(nueva_galleta)
                
                # Actualizar el diccionario de precios
                PRECIOS_GALLETAS[form.nombreGalleta.data] = float(form.precioUnitario.data)
                
                # Confirmar todas las operaciones
                db.session.commit()

                flash("Receta y galleta registradas exitosamente", "success")
                return redirect(url_for('catalogoReceta'))
                
            except Exception as e:
                db.session.rollback()
                print("Error al guardar:", str(e))
                flash("Error al registrar la receta y galleta", "danger")
        else:
            print("Errores de validación:", form.errors)

    return render_template('registroReceta.html', form=form, recetas=recetas)




@app.route('/hbzhbzs', methods=['POST'])
@login_required 
@roles_required('Cocinero', 'Administrador')
def verificar_usuario():
    codigoUsuario = request.form.get('codigoUsuario')
    print(f"Código de usuario recibido: {codigoUsuario}")
    
    cursor = mysql.connection.cursor()
    try:
        # Ejecutar consulta SQL directa
        cursor.execute(
            "SELECT * FROM usuario WHERE codigoUsuario = %s AND (rol = 'Cocinero' OR rol = 'Administrador')", 
            (codigoUsuario,)
        )
        usuario_data = cursor.fetchone()
        
        if usuario_data:
            # Crear instancia de tu clase Usuario con los datos
            usuario = Usuario(
                idUsuario=usuario_data[0],
                nombreCompleto=usuario_data[1],
                apePaterno=usuario_data[2],
                apeMaterno=usuario_data[3],
                usuario=usuario_data[4],
                contrasenia=usuario_data[5],
                correo=usuario_data[6],
                rol=usuario_data[7],
                estatus=usuario_data[8],
                codigoUsuario=usuario_data[9],
                intentos_fallidos=usuario_data[10],
                bloqueado_hasta=usuario_data[11],
                ultimo_cambio_contrasenia=usuario_data[12],
                ultimo_inicio_sesion=usuario_data[13]
            )
            print("Usuario encontrado y verificado")
            flash("Empleado verificado correctamente", "success")
            return redirect(url_for('registro_receta'))
        else:
            print("Usuario no encontrado o no tiene el rol de Cocinero")
            flash("Error: No puedes registrar una receta.", "danger")
            return redirect(url_for('registro_receta'))
    except Exception as e:
        print(f"Error en la consulta: {str(e)}")
        flash("Error al verificar el usuario", "danger")
        return redirect(url_for('registro_receta'))
    finally:
        cursor.close()




@app.route('/hsshsnxb/<int:idReceta>', methods=['GET', 'POST'])
@login_required 
@roles_required('Cocinero', 'Administrador')
def modificar_receta(idReceta):
    receta = Receta.query.get_or_404(idReceta)
    form = RecetaForm(obj=receta)
    
    # Inicializar campos si están vacíos
    if receta.adicional is None:
        receta.adicional = []
    if receta.cantAdicional is None:
        receta.cantAdicional = []
    if receta.unidad is None:
        receta.unidad = []

    if request.method == 'POST':
        # Procesar imagen
        imagen = request.files.get('imagen')
        if imagen and imagen.filename != '':
            try:
                imagen_bin = imagen.read()
                receta.imagen = base64.b64encode(imagen_bin).decode('utf-8')
            except Exception as e:
                flash(f"Error al procesar la imagen: {str(e)}", "danger")
                return render_template('registroReceta2.html', form=form, receta=receta)

        # Procesar ingredientes adicionales
        adicionales = request.form.getlist('adicional[]')
        cantidades = request.form.getlist('cantAdicional[]')
        unidades = request.form.getlist('unidad[]')
        
        # Validar que todos los campos tengan datos
        ingredientes_validos = []
        for a, c, u in zip(adicionales, cantidades, unidades):
            a = str(a).strip() if a is not None else ""
            c = str(c).strip().replace(',', '.') if c is not None else ""
            u = str(u).strip() if u is not None else ""
            
            if a and c and u:
                try:
                    # Verificar que la cantidad sea numérica
                    float(c)
                    ingredientes_validos.append((a, c, u))
                except ValueError:
                    flash(f"La cantidad '{c}' no es un número válido", "danger")
                    return render_template('registroReceta2.html', form=form, receta=receta)
            elif any([a, c, u]) and not all([a, c, u]):
                flash("Todos los campos de ingredientes adicionales deben estar completos", "danger")
                return render_template('registroReceta2.html', form=form, receta=receta)

        # Actualizar los datos de la receta
        try:
            # Actualizar campos del formulario
            form.populate_obj(receta)
            
            # Actualizar ingredientes adicionales
            receta.adicional = [ing[0] for ing in ingredientes_validos] if ingredientes_validos else []
            receta.cantAdicional = [ing[1] for ing in ingredientes_validos] if ingredientes_validos else []
            receta.unidad = [ing[2] for ing in ingredientes_validos] if ingredientes_validos else []

            db.session.commit()
            flash("Receta actualizada correctamente", "success")
            return redirect(url_for('catalogoReceta'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error al actualizar la receta: {str(e)}", "danger")

    return render_template('registroReceta2.html', form=form, receta=receta)





@app.route('/eliminar_receta/<int:idReceta>', methods=['POST'])
@login_required 
@roles_required('Cocinero', 'Administrador')
def eliminar_receta(idReceta):
    receta = Receta.query.get_or_404(idReceta)
    receta.estatus = 'Inactivo'
    db.session.commit()
    flash('Receta marcada como Inactiva', 'success')
    return redirect(url_for('registro_receta'))


#-------------------------------------------------------------------------------------------------------------------


# ----------------------------------CODIGO DE XIMENA ----------------------------------------------------




# ------------------------------------------CODGO DE JUAN -------------------------------------------------

def sanitize_input(value):
    """ Sanitiza la entrada del usuario eliminando caracteres peligrosos """
    if value:
        value = value.strip()  # Elimina espacios en los extremos
        value = re.sub(r'[<>]', '', value)  # Evita etiquetas HTML/JS
        return value
    return ""

#VERIFICACIÓN DE JUAN ------------------------------------------------------------------
import sqlite3  # o el conector de tu base de datos

# Función para verificar usuario
def verificar_usuario(codigo):
    """Verifica si el código de usuario existe y tiene rol válido"""
    try:
        # Usa las mismas credenciales que en DevelopmentConfig
        connection = pymysql.connect(
            host='127.0.0.1',  # Cambiado de 'localhost' a '127.0.0.1'
            user='root',       # Cambiado a 'root'
            password='alejandro.com13',   # Cambiado a 'root'
            database='cookylanda',
            cursorclass=pymysql.cursors.DictCursor
        )
        
        with connection.cursor() as cursor:
            cursor.execute("SELECT rol FROM usuario WHERE codigoUsuario = %s", (codigo,))
            resultado = cursor.fetchone()
            
        connection.close()
        
        if resultado and resultado['rol'] in ['Cocinero', 'Administrador']:
            return True
        return False
        
    except Exception as e:
        print(f"Error al verificar usuario: {e}")
        return False
    
# Ruta para verificación AJAX
@app.route('/verificar_codigo/<codigo>')
def verificar_codigo(codigo):
    if verificar_usuario(codigo):
        return jsonify({'valido': True})
    return jsonify({
        'valido': False,
        'mensaje': 'Acceso denegado - Código inválido o sin permisos suficientes'
    })

# Decorador para verificación de autorización
def requiere_autorizacion(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            codigo_usuario = request.form.get('codigoUsuario')
            if not verificar_usuario(codigo_usuario):
                flash('Acceso denegado: Código inválido o sin permisos suficientes', 'danger')
                return redirect(request.referrer or url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/materia', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador','Cocinero')
def materia():
    # Diccionario de unidades por producto
    unidades_por_producto = {
        # Productos líquidos (litros)
        "Mantequilla derretida": "litros",
        "Esencia de vainilla": "litros",
        "Mermelada de fresa": "litros",
        "Esencia de chicle": "litros",
        "Mermelada de frambuesa": "litros",
        "Jugo de limon": "litros",
        "Leche": "litros",
        # Huevos (unidades)
        "Huevo": "unidades",
        # El resto son kilos por defecto
    }
    
    # Obtener todos los registros de la tabla Materia
    materias = Materia.query.all()
    
    # Convertir los objetos Materia a diccionarios incluyendo la unidad
    materias_serializadas = []
    for materia in materias:
        unidad = unidades_por_producto.get(materia.nombreProducto, "kilos")
        materias_serializadas.append({
            "nombreProducto": materia.nombreProducto,
            "cantidad": float(materia.cantidad),
            "unidad": unidad
        })
    
    # Pasar los datos a la plantilla
    return render_template("materia.html", materias=materias_serializadas)

@app.route('/compra', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador')
def compra():
    form = CompraForm()
    compras = Compra.query.all()
    proveedores = Proveedor.query.all()
    proveedores_options = [f"{p.idProveedor} - {p.empresa}" for p in proveedores]
    
    # Crear un diccionario de proveedores para fácil acceso
    proveedores_dict = {p.idProveedor: p.empresa for p in proveedores}
    
    # Serializar compras para la vista incluyendo nombre de empresa
    compras_serializadas = []
    for compra in compras:
        compra_dict = {
            "idCompra": compra.idCompra,
            "fechaCompra": compra.fechaCompra.isoformat(),
            "proveedor_id": compra.proveedor,  # Mantener el ID para referencia
            "proveedor_nombre": proveedores_dict.get(int(compra.proveedor)),  # Obtener nombre
            "total": float(compra.total),
            "detalles": [detalle.to_dict() for detalle in compra.detalles]
        }
        compras_serializadas.append(compra_dict)

    return render_template("compra.html",
                            compras=compras_serializadas, 
                            proveedores=proveedores_options)


@app.route('/registroCompra', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador')
@requiere_autorizacion
def registroCompra():
    form = CompraForm()
    compras = Compra.query.all()
    proveedores = Proveedor.query.filter_by(estatus='Activo').all()
    proveedores_options = [f"{p.idProveedor} - {p.empresa}" for p in proveedores]

    
    # Serializar compras para la vista
    compras_serializadas = []
    for compra in compras:
        compra_dict = {
            "idCompra": compra.idCompra,
            "fechaCompra": compra.fechaCompra.isoformat(),
            "proveedor": compra.proveedor,
            "total": float(compra.total),
            "detalles": [detalle.to_dict() for detalle in compra.detalles]
        }
        compras_serializadas.append(compra_dict)

    if request.method == 'POST':
        print("🔹 Datos del formulario recibidos:", request.form)

        if 'submit_agregar' in request.form:
            try:
                # Obtener datos del formulario
                codigo_usuario = request.form.get('codigoUsuario')
                total = request.form.get('total')
                proveedor = request.form.get('proveedor')
                
                # Obtener productos desde los campos ocultos
                productos = []
                i = 0
                while True:
                    producto_key = f'productos[{i}][producto]'
                    if producto_key not in request.form:
                        break
                    
                    producto = request.form[producto_key]
                    cantidad = request.form[f'productos[{i}][cantidad]']
                    presentacion = request.form[f'productos[{i}][presentacion]']
                    
                    productos.append({
                        'producto': producto,
                        'cantidad': Decimal(cantidad),
                        'presentacion': presentacion
                    })
                    i += 1

                # Validar que hay productos
                if not productos:
                    flash("No hay productos en la compra", "danger")
                    return redirect(url_for('registroCompra'))

                # Crear nueva compra
                nueva_compra = Compra(
                    fechaCompra=datetime.now(),
                    proveedor=proveedor,
                    total=total,
                    estatus="activo",
                    codigoUsuario=codigo_usuario
                )
                db.session.add(nueva_compra)
                db.session.commit()

                print(f"🔍 Nueva compra ID: {nueva_compra.idCompra}")

                # Procesar cada producto
                for item in productos:
                    print(f"🛒 Agregando detalle: {item['producto']}, cantidad: {item['cantidad']}")

                    # Actualizar o crear materia prima
                    materia = Materia.query.filter_by(nombreProducto=item['producto']).first()
                    if materia:
                        materia.cantidad += item['cantidad']
                    else:
                        nueva_materia = Materia(
                            nombreProducto=item['producto'],
                            cantidad=item['cantidad'],
                            fechaCompra=datetime.now()
                        )
                        db.session.add(nueva_materia)

                    # Crear detalle de compra
                    detalle = DetalleCompra(
                        idCompra=nueva_compra.idCompra,
                        nombreProducto=item['producto'],
                        cantidad=item['cantidad'],
                        presentacion=item['presentacion']
                    )
                    db.session.add(detalle)

                db.session.commit()
                flash("Compra realizada con éxito", "success")
                print("✅ Compra guardada en la BD con éxito")
                return redirect(url_for('registroCompra'))

            except Exception as e:
                db.session.rollback()
                flash(f"Error al confirmar compra: {e}", "danger")
                print(f"❌ Error al confirmar compra: {e}")
                return redirect(url_for('registroCompra'))

    return render_template("registroCompra.html", 
                         form=form, 
                         compras=compras_serializadas, 
                         proveedores=proveedores_options)



@app.route('/registroProveedores', methods=['GET', 'POST'])
@login_required
@roles_required('Administrador')
@requiere_autorizacion
def registroProveedores():
    form = ProveedorForm()
    proveedores = Proveedor.query.filter_by(estatus='Activo').all()

    if request.method == 'POST':  
        if form.validate_on_submit():
            codigo_usuario = sanitize_input(request.form.get("codigoUsuario"))

            # Validar que al menos un producto tenga datos
            has_products = any(
                request.form.get(f'productos-{i}-nombre', '').strip()
                for i in range(len(request.form))
                if f'productos-{i}-nombre' in request.form
            )

            if not has_products:
                flash("Debe agregar al menos un producto", "danger")
                return render_template("registroProveedor.html", form=form, proveedores=proveedores)

            try:
                if 'submit_agregar' in request.form:
                    # Crear el proveedor
                    nuevo_proveedor = Proveedor(
                        nombreProveedor=sanitize_input(form.nombre.data),
                        direccion=sanitize_input(form.direccion.data),
                        telefono=sanitize_input(form.telefono.data),
                        correo=sanitize_input(form.correo.data),
                        tipoVendedor=sanitize_input(form.vendedor.data),
                        empresa=sanitize_input(form.empresa.data),
                        codigoUsuario=codigo_usuario
                    )
                    db.session.add(nuevo_proveedor)
                    db.session.flush()
                    
                    # Procesar productos
                    i = 0
                    while f'productos-{i}-nombre' in request.form:
                        nombre = sanitize_input(request.form.get(f'productos-{i}-nombre'))
                        if nombre:
                            try:
                                precio = float(request.form.get(f'productos-{i}-precio', '0'))
                                if precio <= 0:
                                    raise ValueError("El precio debe ser mayor a cero")
                                
                                db.session.add(Producto(
                                    nombre=nombre,
                                    precio=precio,
                                    idProveedor=nuevo_proveedor.idProveedor
                                ))
                            except ValueError as e:
                                flash(f"Error en el precio del producto {i+1}: {str(e)}", "danger")
                                db.session.rollback()
                                return render_template("registroProveedor.html", form=form, proveedores=proveedores)
                        i += 1

                    db.session.commit()
                    flash("Proveedor y productos agregados correctamente", "success")

                elif 'submit_modificar' in request.form:
                    idProveedor = request.form.get('idProveedor')
                    if idProveedor:
                        proveedor = Proveedor.query.get(idProveedor)
                        if proveedor:
                            # Actualizar datos del proveedor
                            proveedor.nombreProveedor = sanitize_input(form.nombre.data)
                            proveedor.direccion = sanitize_input(form.direccion.data)
                            proveedor.telefono = sanitize_input(form.telefono.data)
                            proveedor.correo = sanitize_input(form.correo.data)
                            proveedor.tipoVendedor = sanitize_input(form.vendedor.data)
                            proveedor.empresa = sanitize_input(form.empresa.data)
                            proveedor.codigoUsuario = codigo_usuario
                            
                            # Eliminar productos existentes
                            Producto.query.filter_by(idProveedor=idProveedor).delete()
                            
                            # Agregar nuevos productos
                            i = 0
                            while f'productos-{i}-nombre' in request.form:
                                nombre = sanitize_input(request.form.get(f'productos-{i}-nombre'))
                                if nombre:
                                    precio = float(request.form.get(f'productos-{i}-precio', '0'))
                                    db.session.add(Producto(
                                        nombre=nombre,
                                        precio=precio,
                                        idProveedor=idProveedor
                                    ))
                                i += 1
                            
                            db.session.commit()
                            flash("Proveedor y productos modificados correctamente", "success")
                        else:
                            flash("Proveedor no encontrado", "danger")

                elif 'submit_eliminar' in request.form:
                    idProveedor = request.form.get('idProveedor')
                    if idProveedor:
                        proveedor = Proveedor.query.get(idProveedor)
                        if proveedor:
                            proveedor.estatus = 'Inactivo'
                            Producto.query.filter_by(idProveedor=idProveedor).update({'estatus': 'Inactivo'})
                            db.session.commit()
                            flash("Proveedor y productos marcados como inactivos", "success")
                        else:
                            flash("Proveedor no encontrado", "danger")

                return redirect(url_for('registroProveedores'))

            except Exception as e:
                db.session.rollback()
                flash(f"Error al procesar la solicitud: {str(e)}", "danger")
                return render_template("registroProveedor.html", form=form, proveedores=proveedores)

    return render_template("registroProveedor.html", form=form, proveedores=proveedores)


def obtener_presentaciones_por_producto(nombre_producto):
    """Función auxiliar para determinar presentaciones disponibles por producto"""
    # Puedes personalizar esto según tus necesidades
    presentaciones_base = ["KG", "Bolsa", "Saco", "Costal"]
    presentaciones_liquidos = ["Litro", "Galón", "Caja"]
    
    if nombre_producto in ["Mantequilla derretida", "Esencia de vainilla", "Jugo de limón"]:
        return presentaciones_liquidos
    elif nombre_producto == "Huevo":
        return ["CajaH", "Bolsa"]
    else:
        return presentaciones_base

@app.route('/obtener_productos_proveedor/<int:proveedor_id>')
@login_required
@roles_required('Administrador')
def obtener_productos_proveedor(proveedor_id):
    try:
        # Verificar que el proveedor existe
        proveedor = Proveedor.query.get(proveedor_id)
        if not proveedor:
            return jsonify({'error': 'Proveedor no encontrado'}), 404
        
        # Obtener productos activos del proveedor
        productos = Producto.query.filter_by(
            idProveedor=proveedor_id,
            estatus='Activo'
        ).order_by(Producto.nombre).all()
        
        # Preparar respuesta JSON
        productos_json = [{
            'id': producto.idProducto,
            'nombre': producto.nombre,
            'precio': float(producto.precio),
            'presentaciones': obtener_presentaciones_por_producto(producto.nombre)
        } for producto in productos]
        
        return jsonify(productos_json)
    
    except Exception as e:
        print(f"Error al obtener productos: {str(e)}")
        return jsonify({'error': 'Error al cargar productos'}), 500

@app.route('/obtener_precio_producto', methods=['POST'])
@login_required
@roles_required('Vendedor','Administrador')
def obtener_precio_producto():
    data = request.get_json()
    producto = data.get('producto')

    # Buscar el producto en la base de datos
    producto_db = Producto.query.filter_by(nombre=producto).first()

    if producto_db:
        return jsonify({'precio': producto_db.precio}), 200
    else:
        return jsonify({'error': 'Producto no encontrado'}), 404
    
#ROCHA ---------------------------------------------------------------------------------

# Rutas principales
@app.route("/stock", methods=["GET", "POST"])
@app.route("/stock", methods=["GET", "POST"])
@login_required
@roles_required('Cocinero')
def stock():
    create_form = TablaProduccion(request.form)

    # Consultar correctamente la tabla CantidadGalletas
    stockGalletas = CantidadGalletas.query.all()

    return render_template("stock.html", form=create_form, stockGalletas=stockGalletas)

@app.route("/detalles", methods=["GET"])
@login_required
@roles_required('Cocinero', 'Administrador')
def detalles():
    id = request.args.get("id")

    # Validar si el ID fue proporcionado
    if not id:
        flash("ID de galleta no proporcionado", "danger")
        return redirect(url_for("index"))

    # Buscar la galleta por ID
    galleta = CantidadGalletas.query.filter_by(id=id).first()

    if not galleta:
        flash("Galleta no encontrada", "danger")
        return redirect(url_for("index"))

    return render_template(
        "detalles.html",
        id=galleta.id,
        nombreGalleta=galleta.nombreGalleta,
        cantidad=galleta.cantidad,
        proceso=galleta.proceso,
    )

@app.route("/notificaciones_produccion")
@login_required
def notificaciones_produccion():
    return render_template("notificaciones_produccion.html")


@app.route("/produccion_cocina", methods=["GET"])
@login_required
@roles_required('Cocinero', 'Administrador')
def produccion_cocina():
    # Consulta optimizada para evitar duplicados
    subquery = db.session.query(
        StockGalletas.nombreGalleta,
        func.max(StockGalletas.cantidadPiezas).label('max_cantidad')
    ).group_by(StockGalletas.nombreGalleta).subquery()

    recetas = db.session.query(
        Receta,
        subquery.c.max_cantidad
    ).outerjoin(
        subquery, Receta.nombreGalleta == subquery.c.nombreGalleta
    ).filter(
        Receta.estatus == "Activo"
    ).all()

    # Verificación de datos (opcional)
    for receta, cantidad in recetas:
        print(f"\nReceta: {receta.nombreGalleta} - Stock: {cantidad}")

    return render_template("produccion_cocina.html", recetas=recetas)


@app.route("/nueva_receta", methods=["GET", "POST"])
@login_required
@roles_required('Cocinero', 'Administrador')
def nueva_receta():
    form = FormularioRecetas()
    if request.method == "POST" and form.validate():
        # Procesar la imagen subida
        imagen = None
        if form.imagen.data:
            imagen_bin = form.imagen.data.read()  # Leer el archivo binario
            imagen = base64.b64encode(imagen_bin).decode('utf-8')  # Convertir a Base64

        # Crear la nueva receta
        nueva_receta = Receta(
            nombreGalleta=form.nombreGalleta.data,
            procedimiento=form.procedimiento.data,
            imagen=imagen,  # Guardar en formato Base64
            estatus="Activo",
        )
        db.session.add(nueva_receta)
        db.session.commit()
        flash("Receta añadida exitosamente", "success")
        return redirect(url_for("produccion_cocina"))

    return render_template("formulario_receta.html", form=form)

#PRODUCCIÓN --------------------------------------------------------------------
@app.route('/producir_galletas', methods=['POST','GET'])
@roles_required('Cocinero', 'Administrador')
def producir_galletas():
    try:
        # Obtener datos del request
        data = request.get_json()
        nombre_galleta = data['nombreGalleta']
        cantidad_lotes = int(data['cantidadLotes'])

        
        # Validación básica
        if cantidad_lotes <= 0:
            return jsonify({
                'success': False,
                'message': 'La cantidad de lotes debe ser mayor a cero'
            }), 400

        # Obtener receta de la base de datos
        receta = Receta.query.filter_by(nombreGalleta=nombre_galleta).first()
        
        if not receta:
            return jsonify({
                'success': False,
                'message': 'Receta no encontrada'
            }), 404

        # Configuración de ingredientes estándar
        ingredientes_config = [
            {'key': 'harina', 'campo_ing': 'harIng', 'campo_cant': 'cantHar', 'unidad_receta': 'g', 'unidad_inventario': 'kg', 'tipo': 'peso'},
            {'key': 'huevo', 'campo_ing': 'huvrIng', 'campo_cant': 'cantHuv', 'unidad_receta': 'unidad', 'unidad_inventario': 'unidad', 'tipo': 'unidad'},
            {'key': 'polvo_hornear', 'campo_ing': 'horIng', 'campo_cant': 'cantHor', 'unidad_receta': 'g', 'unidad_inventario': 'kg', 'tipo': 'peso'},
            {'key': 'sal', 'campo_ing': 'salIng', 'campo_cant': 'cantSal', 'unidad_receta': 'g', 'unidad_inventario': 'kg', 'tipo': 'peso'},
            {'key': 'mantequilla', 'campo_ing': 'manIng', 'campo_cant': 'cantMan', 'unidad_receta': 'g', 'unidad_inventario': 'kg', 'tipo': 'peso'},
            {'key': 'azucar', 'campo_ing': 'azurIng', 'campo_cant': 'cantAzur', 'unidad_receta': 'g', 'unidad_inventario': 'kg', 'tipo': 'peso'},
            {'key': 'leche', 'campo_ing': 'LechIng', 'campo_cant': 'cantLech', 'unidad_receta': 'ml', 'unidad_inventario': 'lt', 'tipo': 'volumen'}
        ]

        ingredientes_necesarios = []
        faltantes = []

        # Paso 1: Procesar ingredientes estándar
        for ing in ingredientes_config:
            try:
                nombre_ingrediente = getattr(receta, ing['campo_ing'])
                cantidad_str = str(getattr(receta, ing['campo_cant'])) or "0"
                
                # Calcular según el tipo de ingrediente
                if ing['tipo'] == 'unidad':
                    cantidad = int(float(cantidad_str) * cantidad_lotes)
                else:
                    cantidad_base = float(cantidad_str.replace(',', '.'))
                    
                    # Conversión de unidades
                    if ing['unidad_receta'] == 'g' and ing['unidad_inventario'] == 'kg':
                        cantidad = (cantidad_base * cantidad_lotes) / 1000
                    elif ing['unidad_receta'] == 'ml' and ing['unidad_inventario'] == 'lt':
                        cantidad = (cantidad_base * cantidad_lotes) / 1000
                    else:
                        cantidad = cantidad_base * cantidad_lotes
                
                if cantidad > 0:
                    ingredientes_necesarios.append({
                        'nombre': nombre_ingrediente,
                        'cantidad': cantidad,
                        'unidad': ing['unidad_inventario'],
                        'tipo': ing['tipo']
                    })
                    
            except Exception as e:
                print(f"Error procesando {ing['key']}: {str(e)}")
                continue

        # Paso 2: Procesar ingrediente adicional - VERSIÓN CORREGIDA
        try:
            if receta.adicional and receta.cantAdicional:
                # Los campos JSON ya vienen como listas/diccionarios de Python
                adicionales = receta.adicional
                cantidades = receta.cantAdicional
                unidades = receta.unidad if receta.unidad else ['g'] * len(adicionales)
                
                # Asegurar que todos sean listas
                adicionales = adicionales if isinstance(adicionales, list) else [adicionales]
                cantidades = cantidades if isinstance(cantidades, list) else [cantidades]
                unidades = unidades if isinstance(unidades, list) else [unidades]
                
                # Procesar cada ingrediente adicional
                for i in range(len(adicionales)):
                    nombre_extra = adicionales[i]
                    cantidad_str = str(cantidades[i]).strip()
                    unidad_extra = str(unidades[i]).strip().lower() if i < len(unidades) else 'g'
                    
                    try:
                        cantidad_extra = float(cantidad_str.replace(',', '.'))
                    except ValueError:
                        print(f"Valor no numérico para cantidad adicional: {cantidad_str}")
                        continue
                    
                    # Determinar tipo y conversión de unidades
                    if unidad_extra in ['g', 'gramo', 'gramos']:
                        cantidad = (cantidad_extra * cantidad_lotes) / 1000  # Convertir g a kg
                        unidad_inv = 'kg'
                        tipo = 'peso'
                    elif unidad_extra in ['ml', 'mililitro', 'mililitros']:
                        cantidad = (cantidad_extra * cantidad_lotes) / 1000  # Convertir ml a lt
                        unidad_inv = 'lt'
                        tipo = 'volumen'
                    else:  # unidades
                        cantidad = cantidad_extra * cantidad_lotes
                        unidad_inv = 'unidad'
                        tipo = 'unidad'
                    
                    if cantidad > 0:
                        ingredientes_necesarios.append({
                            'nombre': nombre_extra,
                            'cantidad': cantidad,
                            'unidad': unidad_inv,
                            'tipo': tipo
                        })
                        
                        print(f"Procesando ingrediente extra: {nombre_extra} - {cantidad}{unidad_inv}")
                        
        except Exception as e:
            print(f"Error procesando ingrediente adicional: {str(e)}")
            traceback.print_exc()

        # Paso 3: Verificar disponibilidad
        with db.session.begin_nested():
            for ing in ingredientes_necesarios:
                materia = Materia.query.filter_by(nombreProducto=ing['nombre']).first()
                
                if not materia:
                    faltantes.append({
                        'nombre': ing['nombre'],
                        'necesario': ing['cantidad'],
                        'disponible': 0,
                        'unidad': ing['unidad']
                    })
                    continue
                
                # Comparar considerando el tipo de ingrediente
                try:
                    if ing['tipo'] == 'unidad':
                        disponible = int(materia.cantidad)
                        necesario = int(ing['cantidad'])
                        if disponible < necesario:
                            faltantes.append({
                                'nombre': ing['nombre'],
                                'necesario': necesario,
                                'disponible': disponible,
                                'unidad': ing['unidad']
                            })
                    else:
                        disponible = float(materia.cantidad)
                        necesario = float(ing['cantidad'])
                        
                        if abs(disponible - necesario) > 0.0001 and disponible < necesario:
                            faltantes.append({
                                'nombre': ing['nombre'],
                                'necesario': necesario,
                                'disponible': disponible,
                                'unidad': ing['unidad']
                            })
                except Exception as e:
                    print(f"Error comparando disponibilidad para {ing['nombre']}: {str(e)}")
                    faltantes.append({
                        'nombre': ing['nombre'],
                        'necesario': ing['cantidad'],
                        'disponible': "Error",
                        'unidad': ing['unidad']
                    })

            if faltantes:
                mensajes_proceso = []  # Inicializar la lista
                print("Faltantes detectados:", faltantes)
                print("Mensajes de proceso:", mensajes_proceso)  # Para depuración
    
                # Convertir mensajes_proceso a string si es necesario
                mensaje_principal = "Materia prima insuficiente"
                if mensajes_proceso and isinstance(mensajes_proceso, list) and len(mensajes_proceso) > 0:
                    mensaje_principal = mensajes_proceso[-1]  # Usar el último mensaje como principal
    
                return jsonify({
                    'success': False,
                    'message': mensaje_principal,  # String, no array
                    'faltantes': [{
                        'nombre': item['nombre'],
                        'necesario': float(item['necesario']),
                        'disponible': float(item['disponible']) if isinstance(item['disponible'], (int, float, Decimal)) else 0,
                        'unidad': item['unidad']
                    } for item in faltantes],
                    'procesamiento': mensajes_proceso if isinstance(mensajes_proceso, list) else []
                }), 400

            # Paso 4: Actualizar inventario
            for ing in ingredientes_necesarios:
                materia = Materia.query.filter_by(nombreProducto=ing['nombre']).first()
                if not materia:
                    continue
                    
                try:
                    if ing['tipo'] == 'unidad':
                        materia.cantidad = str(int(materia.cantidad) - int(ing['cantidad']))
                    else:
                        # Para cantidades decimales, trabajar con Decimal para precisión
                        cantidad_actual = Decimal(str(materia.cantidad))
                        cantidad_a_restar = Decimal(str(ing['cantidad']))
                        materia.cantidad = str(cantidad_actual - cantidad_a_restar)
                    
                    print(f"Actualizado inventario: {ing['nombre']} -{ing['cantidad']}{ing['unidad']}")
                except Exception as e:
                    print(f"Error actualizando inventario para {ing['nombre']}: {str(e)}")
                    db.session.rollback()
                    return jsonify({
                        'success': False,
                        'message': f'Error al actualizar el inventario para {ing["nombre"]}',
                        'error': str(e)
                    }), 500

            # Paso 5: Crear registro de producción
            galletas_producidas = cantidad_lotes * 15  # Asumiendo 15 galletas por lote
            nuevo_stock = StockGalletas(
                nombreGalleta=nombre_galleta,
                cantidadPiezas=galletas_producidas,
                fechaPreparacion=date.today()
            )
            db.session.add(nuevo_stock)
            
            db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Producción exitosa: {galletas_producidas} galletas de {nombre_galleta}',
            'detalle': {
                'lotes_producidos': cantidad_lotes,
                'galletas_producidas': galletas_producidas,
                'ingredientes_utilizados': [
                    {
                        'nombre': i['nombre'],
                        'cantidad': i['cantidad'],
                        'unidad': i['unidad']
                    } for i in ingredientes_necesarios
                ]
            }
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error en producción:\n{traceback.format_exc()}")
        return jsonify({
            'success': False,
            'message': 'Error en el proceso de producción',
            'error': str(e),
            'error_detalle': traceback.format_exc()
        }), 500

# ----------------------------------------YOLANDA ------------------------------------------------------------------------------------


#***************************sección cliente********************************************

#file pedido
PEDIDOS_FILE = "pedidos.txt"

def leer_pedidos():
    pedidos = []
    if os.path.exists(PEDIDOS_FILE):
        with open(PEDIDOS_FILE, "r", encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        galleta, modalidad, cantidad, subtotal = line.split("|")
                        pedidos.append({
                            "galleta": galleta,
                            "modalidad": modalidad,
                            "cantidad": int(cantidad),
                            "subtotal": float(subtotal)
                        })
                    except Exception as e:
                        print(f"Error al procesar línea: {line}. Error: {e}")
                        continue
    return pedidos

def guardar_pedido(galleta, modalidad, cantidad, subtotal):
    with open(PEDIDOS_FILE, "a", encoding='utf-8') as f:
        f.write(f"{galleta}|{modalidad}|{cantidad}|{subtotal}\n")

def eliminar_ultimo_pedido():
    if os.path.exists(PEDIDOS_FILE):
        with open(PEDIDOS_FILE, "r", encoding='utf-8') as f:
            lines = f.readlines()
        if lines:
            lines.pop()
            with open(PEDIDOS_FILE, "w", encoding='utf-8') as f:
                f.writelines(lines)

def calcular_total_pedido():
    pedidos = leer_pedidos()
    total = sum(pedido["subtotal"] for pedido in pedidos)
    return total




@app.route("/catalogoGalletas")
@login_required
@roles_required('Cliente')
def catalogo_galletas():
    # Obtener todas las galletas de la base de datos
    galletas = Galletas.query.order_by(Galletas.nombre).all()
    
    # Procesar las galletas para el carrusel
    grupos_galletas = []
    grupo_actual = []
    
    # Diccionario de reemplazos especiales
    reemplazos_especiales = {
        "é": "e",
        "á": "a",
        "í": "i",
        "ó": "o",
        "ú": "u",
        "ñ": "n",
        "DulcedeLeche": "DulceDeLeche"  # Caso especial
    }
    
    for galleta in galletas:
        # Eliminar "Galleta de " o "Galleta " del nombre
        nombre_base = galleta.nombre.replace("Galleta de ", "").replace("Galleta ", "")
        
        # Aplicar transformaciones al nombre de la imagen
        nombre_imagen = nombre_base
        # Eliminar espacios y caracteres no deseados
        nombre_imagen = nombre_imagen.replace(" ", "").replace("(", "").replace(")", "")
        # Reemplazar acentos y caracteres especiales
        for original, reemplazo in reemplazos_especiales.items():
            nombre_imagen = nombre_imagen.replace(original, reemplazo)
        
        # Crear objeto con los datos necesarios
        galleta_data = {
            'nombre': galleta.nombre,
            'precio': f"${galleta.precioUnitario:.2f}",
            'imagen': f"../static/img/Galleta{nombre_imagen}.png",
            'id': galleta.idGalleta
        }
        
        grupo_actual.append(galleta_data)
        
        # Agrupar de 3 en 3
        if len(grupo_actual) == 3:
            grupos_galletas.append(grupo_actual)
            grupo_actual = []
    
    # Agregar el último grupo si no está completo
    if grupo_actual:
        grupos_galletas.append(grupo_actual)
    
    return render_template("catalogoGalletas.html", grupos_galletas=grupos_galletas)


#agrega las galletas desde las fotos en catalogo
@app.route("/agregar_pedido", methods=['POST'])
@login_required
@roles_required('Cliente')
def agregar_pedido():
    try:
        galleta_nombre = request.form.get('galleta_nombre')
        modalidad = request.form.get('modalidad')
        cantidad = request.form.get('cantidad')
        galleta_precio = float(request.form.get('galleta_precio'))
        
        # Validar la cantidad
        try:
            cantidad = int(cantidad)
            if cantidad <= 0:
                flash('La cantidad debe ser mayor a cero', 'danger')
                return redirect(url_for('catalogo_galletas'))
        except ValueError:
            flash('La cantidad debe ser un número válido', 'danger')
            return redirect(url_for('catalogo_galletas'))
        
        # Calcular el subtotal
        subtotal = calcular_subtotal(galleta_nombre, modalidad, cantidad)
        
        # Guardar el pedido
        guardar_pedido(galleta_nombre, modalidad, cantidad, subtotal)
        
        flash(f'Se agregó {galleta_nombre} al pedido correctamente', 'success')
        return redirect(url_for('catalogo_galletas'))
        
    except Exception as e:
        flash(f'Error al agregar el pedido: {str(e)}', 'danger')
        return redirect(url_for('catalogo_galletas'))
    
    
#pedido del modulo del cliente
@app.route("/pedidoCliente", methods=["GET", "POST"])
@login_required
@roles_required('Cliente')
def carrito_compras():
    galletas = Galletas.query.with_entities(Galletas.nombre).all()
    galletas = [g[0] for g in galletas]
    usuario_actual = Usuario.query.get(current_user.id)

    
    form = PedidoForm()  # Sin pasar request.form aquí
    carrito = leer_pedidos()
    total = calcular_total_pedido()
    
    if request.method == "POST":
        if "agregar" in request.form:
            form = PedidoForm(request.form)  # Ahora sí pasamos request.form
            
            if form.validate():  # Cambia validate_on_submit() por validate()
                galleta = request.form.get("galleta", "").strip()
                modalidad = request.form.get("modalidad", "").strip()
                cantidad = form.cantidad.data
        
                subtotal = calcular_subtotal(galleta, modalidad, cantidad)
                if subtotal > 0:
                    guardar_pedido(galleta, modalidad, cantidad, subtotal)
                    flash("Galleta agregada al pedido", "success")
                    return redirect(url_for("carrito_compras"))  
                else:
                    flash("Error al calcular el subtotal", "error")
            # No hagas redirect aquí si hay errores
            
        elif "eliminarGalleta" in request.form:
            eliminar_ultimo_pedido()
            flash("Última galleta eliminada del pedido", "info")
            return redirect(url_for("carrito_compras"))
        
        elif "finalizarPedido" in request.form:
            if not carrito:
                flash("No hay galletas en el pedido", "error")
                return redirect(url_for("carrito_compras"))
            
            usuario_id = request.form.get("usuario_id", type=int)
            if usuario_id is None:
                flash("Por favor, selecciona un usuario válido", "error")
                return redirect(url_for("carrito_compras"))
            
            usuario = Usuario.query.get(usuario_id)
            if not usuario:
                flash("Usuario no encontrado", "error")
                return redirect(url_for("carrito_compras"))
            
            fecha_entrega = request.form.get("fecha_entrega", "")
            
            # Validación del anticipo
            try:
                anticipo = float(request.form.get("anticipo", 0))
                if anticipo < 0:
                    flash("No se permiten valores negativos en el anticipo", "error")
                    return redirect(url_for("carrito_compras"))
            except ValueError:
                flash("El anticipo debe ser un valor numérico válido", "error")
                return redirect(url_for("carrito_compras"))
            
            try:
                fecha_entrega_obj = datetime.strptime(fecha_entrega, '%Y-%m-%d').date()
                if fecha_entrega_obj < date.today():
                    flash("La fecha de entrega no puede ser anterior a hoy", "error")
                    return redirect(url_for("carrito_compras"))
            except ValueError:
                flash("Fecha de entrega inválida", "error")
                return redirect(url_for("carrito_compras"))
            
            total_pedido = calcular_total_pedido()
            
            # Validar que el anticipo no sea mayor al total
            if anticipo > total_pedido:
                flash("El anticipo no puede ser mayor al total del pedido", "error")
                return redirect(url_for("carrito_compras"))
            
            resto_a_pagar = total_pedido - anticipo
            
            pedido = Pedido(
                idUsuario=usuario.idUsuario,
                fechaApartado=datetime.now(),
                fechaDeEntrega=fecha_entrega_obj,
                anticipo=anticipo,
                totalApagar=total_pedido,
                estado='Pendiente'
            )
            
            db.session.add(pedido)
            db.session.flush()
            
            resto_a_pagar_por_detalle = resto_a_pagar / len(carrito) if carrito else 0
            
            for item in carrito:
                galleta_db = Galletas.query.filter_by(nombre=item["galleta"]).first()
                if not galleta_db:
                    db.session.rollback()
                    flash(f"Galleta {item['galleta']} no encontrada", "error")
                    return redirect(url_for("carrito_compras"))
                
                detalle = DetallePedido(
                    idPedido=pedido.idPedido,
                    idGalleta=galleta_db.idGalleta,
                    Presentacion=item["modalidad"],
                    cantidad=item["cantidad"],
                    restoApagar=resto_a_pagar_por_detalle
                )
                db.session.add(detalle)

            db.session.commit()

            # Guardar el ID del usuario en la sesión
            session['usuario_id'] = usuario.idUsuario
            session['usuario_nombre'] = usuario.nombreCompleto
            
            with open(PEDIDOS_FILE, "w", encoding='utf-8') as f:
                f.write("")
            
            flash("Pedido realizado con éxito", "success")
            return redirect(url_for("listado_pedidos"))
    
    return render_template("carritoCompras.html",
                            form=form,
                            galletas=galletas,
                            usuario_actual=usuario_actual,
                            carrito=carrito,
                            total=total)


@app.route("/historicoCompras")
@login_required
@roles_required('Cliente')
def listado_pedidos():
    try:
        usuario = Usuario.query.get(current_user.id)
        if not usuario:
            flash("No se encontró la información del cliente", "error")
            return redirect(url_for("index"))

        pedidos = Pedido.query.filter_by(idUsuario=usuario.idUsuario)\
                                .order_by(Pedido.fechaApartado.desc())\
                                .all()

        pedidos_con_detalle = []
        for pedido in pedidos:
            detalles = DetallePedido.query.filter_by(idPedido=pedido.idPedido).all()
            pedidos_con_detalle.append({
                'pedido': pedido,
                'detalles': detalles,
                'galletas': [Galletas.query.get(detalle.idGalleta) for detalle in detalles]
            })

        return render_template(
            "listadoPedidos.html",
            pedidos_con_detalle=pedidos_con_detalle,
            usuario=usuario,
            format_date=lambda d: d.strftime('%d/%m/%Y') if d else ''
        )

    except Exception as e:
        db.session.rollback()
        flash("Error al cargar el historial de pedidos", "error")
        return redirect(url_for("index"))

@app.route("/cancelar_Historico/<int:pedido_id>", methods=["POST"])
@login_required
@roles_required('Cliente')
def cancelar_historico(pedido_id):
    # Verificar que el pedido pertenece al usuario en sesión
    usuario_id = session.get('usuario_id')
    if not usuario_id:
        flash("No se ha identificado al cliente", "error")
        return redirect(url_for("index"))
    
    pedido = Pedido.query.filter_by(idPedido=pedido_id, idUsuario=usuario_id).first()
    
    if not pedido:
        flash("Pedido no encontrado o no pertenece al usuario", "error")
        return redirect(url_for("listado_pedidos"))
    
    if pedido.estado != 'Pendiente':
        flash("Solo se pueden cancelar pedidos pendientes", "error")
        return redirect(url_for("listado_pedidos"))
    
    # Cambiar el estado del pedido
    pedido.estado = 'Cancelado'
    db.session.commit()
    
    flash("Pedido cancelado correctamente", "success")
    return redirect(url_for("listado_pedidos"))


#*****************seccion dashboard****************************************************

@app.route("/dashboard")
@login_required
@roles_required('Administrador','Vendedor')
def dashboard():
    # 1. Ventas del día
    hoy = datetime.now().date()
    ventas_hoy = db.session.query(func.count(Venta.idVenta)).filter(
        func.date(Venta.fechaVenta) == hoy
    ).scalar()
    
    total_hoy = db.session.query(func.sum(Venta.total)).filter(
        func.date(Venta.fechaVenta) == hoy
    ).scalar() or 0
    
    # 2. Datos de pedidos
    pedidos_pendientes = Pedido.query.filter_by(estado='Pendiente').count()
    total_pendiente = db.session.query(
        func.sum(Pedido.totalApagar - Pedido.anticipo)
    ).filter(Pedido.estado == 'Pendiente').scalar() or 0
    
    # 3. Gráfico de ventas semanales
    ventas_semanales = db.session.query(
        func.date(Venta.fechaVenta).label('fecha'),
        func.sum(Venta.total).label('total')
    ).filter(func.date(Venta.fechaVenta) >= hoy - timedelta(days=7)
    ).group_by(func.date(Venta.fechaVenta)
    ).order_by(func.date(Venta.fechaVenta)).all()
    
    df_ventas = pd.DataFrame(ventas_semanales, columns=['Fecha', 'Total'])
    graph_ventas = px.bar(df_ventas, x='Fecha', y='Total',
                                title='Ventas de los Últimos 7 Días',
                                color='Total',
                                color_continuous_scale='Bluered')  # Cambiado a escala azul-rojo
    
    # 4. Gráfico de productos más vendidos
    productos_vendidos = db.session.query(
        Galletas.nombre,
        func.sum(DetalleVenta.cantidad).label('total_vendido')
    ).join(DetalleVenta, DetalleVenta.idGalleta == Galletas.idGalleta
    ).join(Venta, Venta.idVenta == DetalleVenta.idVenta
    ).filter(func.date(Venta.fechaVenta) >= hoy - timedelta(days=30)
    ).group_by(Galletas.nombre
    ).order_by(func.sum(DetalleVenta.cantidad).desc()
    ).limit(5).all()
    
    df_productos = pd.DataFrame(productos_vendidos, columns=['Producto', 'Cantidad'])
    graph_productos = px.pie(df_productos, values='Cantidad', names='Producto', 
                                title='Top 5 Productos Más Vendidos (Últimos 30 días)',
                                color_discrete_sequence=px.colors.sequential.RdBu)  # Esquema de colores definido
    
    # 5. Gráfico de presentaciones más populares
    presentaciones_populares = db.session.query(
        DetalleVenta.Presentacion,
        func.count(DetalleVenta.idDetalle).label('total')
    ).join(Venta, Venta.idVenta == DetalleVenta.idVenta
    ).filter(func.date(Venta.fechaVenta) >= hoy - timedelta(days=30)
    ).group_by(DetalleVenta.Presentacion
    ).order_by(func.count(DetalleVenta.idDetalle).desc()
    ).all()
    
    df_presentaciones = pd.DataFrame(presentaciones_populares, columns=['Presentacion', 'Total'])
    graph_presentaciones = px.pie(df_presentaciones, values='Total', names='Presentacion',
                                title='Presentaciones Más Populares (Últimos 30 días)',
                                hole=0.3,
                                color_discrete_sequence=px.colors.sequential.Plasma)  # Esquema de colores definido
    
    # 6. Gráfico de estado de pedidos
    estado_pedidos = db.session.query(
        Pedido.estado,
        func.count(Pedido.idPedido).label('total')
    ).group_by(Pedido.estado).all()
    
    df_estado_pedidos = pd.DataFrame(estado_pedidos, columns=['Estado', 'Total'])
    graph_estado_pedidos = px.pie(df_estado_pedidos, values='Total', names='Estado',
                                    title='Distribución de Estados de Pedidos',
                                    color_discrete_sequence=px.colors.qualitative.Pastel)
    
    return render_template('dashboard.html',
                            ventas_hoy=ventas_hoy,
                            total_hoy=total_hoy,
                            pedidos_pendientes=pedidos_pendientes,
                            total_pendiente=total_pendiente,
                            graph_ventas=graph_ventas.to_html(full_html=False),
                            graph_productos=graph_productos.to_html(full_html=False),
                            graph_presentaciones=graph_presentaciones.to_html(full_html=False),
                            graph_estado_pedidos=graph_estado_pedidos.to_html(full_html=False))
    
    


#***********************sección de ventas***********************************************************************



@app.route("/menu")
@login_required
@roles_required('Vendedor', 'Administrador')
def menuVentas():
    return render_template("menuventas.html")

# Archivos para guardar las ventas, tickets y solicitudes a produccion
VENTAS_FILE = "ventas.txt"
TICKET_FILE = "ticket.txt"
SOLICITUDES_FILE = "solicitud.txt"


#NOTIFICACIÓN JUAN ----------------------------------------------------------------------
#file pedido
SOLICITUDES_FILE = "solicitud.txt"
@app.route('/mostrar_notificacionesJ')
def mostrar_notificacionesJ():
    # Obtener el stock de galletas para la tabla principal
    stock_galletas = StockGalletas.query.order_by(StockGalletas.nombreGalleta).all()
    hoy = date.today()
    for galleta in stock_galletas:
        dias_restantes = (galleta.fechaPreparacion + timedelta(days=14) - hoy).days
        galleta.dias_restantes = max(0, dias_restantes)
    
    # Leer las solicitudes existentes
    solicitudes = []
    if os.path.exists(SOLICITUDES_FILE):
        with open(SOLICITUDES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        mensaje, estado = line.split('|')
                        solicitudes.append({'mensaje': mensaje, 'estado': estado})
                    except:
                        continue
    
    return render_template("produccion_cocina.html", 
                        stock_galletas=stock_galletas,
                        mostrar_modal_notificaciones=True,
                        solicitudes=solicitudes)

@app.route('/eliminar_solicitud/<int:index>', methods=['POST'])
def eliminar_solicitud(index):
    # Leer todas las solicitudes
    if os.path.exists(SOLICITUDES_FILE):
        with open(SOLICITUDES_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Eliminar la línea correspondiente al índice
        if 0 <= index < len(lines):
            lines.pop(index)
            
            # Escribir las líneas restantes de vuelta al archivo
            with open(SOLICITUDES_FILE, 'w', encoding='utf-8') as f:
                f.writelines(lines)
    
    return redirect(url_for('mostrar_notificacionesJ'))

# Precios de las galletas
PRECIOS_GALLETAS = {
    "Galleta de Arándano": 12,
    "Galleta de Bombón": 10,
    "Galleta de Café": 11,
    "Galleta de Cajeta Agrio": 13,
    "Galleta de Cherry": 12,
    "Galleta de Chicle": 10,
    "Galleta de Chispas": 10,
    "Galleta de Chokis": 12,
    "Galleta Combinada": 13,
    "Galleta de Corazón": 12,
    "Galleta de Crema Batida": 14,
    "Galleta de Delfines": 13,
    "Galleta de Dulce de Leche": 12,
    "Galleta de Durazno": 12,
    "Galleta Estrella": 11,
    "Galleta Extra Chocolate": 14,
    "Galleta Flor": 10,
    "Galleta de Fresa": 12,
    "Galleta de Frutos Rojos": 13,
    "Galleta de Limón": 11
}

# Cantidades por modalidad
CANTIDADES_MODALIDAD = {
    "Caja Chica (4 galletas)": 4,
    "Caja Grande (12 galletas)": 12,
    "Medio Kilo (20 galletas)": 20,
    "Kilo completo (40 galletas)": 40,
    "suelta": 1
}

def leer_ventas():
    ventas = []
    if os.path.exists(VENTAS_FILE):
        with open(VENTAS_FILE, "r", encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        galleta, modalidad, cantidad, subtotal = line.split("|")
                        ventas.append({
                            "galleta": galleta,
                            "modalidad": modalidad,
                            "cantidad": int(cantidad),
                            "subtotal": float(subtotal)
                        })
                    except Exception as e:
                        print(f"Error al procesar línea: {line}. Error: {e}")
                        continue
    return ventas

def guardar_venta(galleta, modalidad, cantidad, subtotal):
    with open(VENTAS_FILE, "a", encoding='utf-8') as f:
        f.write(f"{galleta}|{modalidad}|{cantidad}|{subtotal}\n")

def eliminar_ultima_venta():
    if os.path.exists(VENTAS_FILE):
        with open(VENTAS_FILE, "r", encoding='utf-8') as f:
            lines = f.readlines()
        if lines:
            lines.pop()
            with open(VENTAS_FILE, "w", encoding='utf-8') as f:
                f.writelines(lines)

def calcular_total():
    ventas = leer_ventas()
    total = sum(venta["subtotal"] for venta in ventas)
    return total




def calcular_subtotal(galleta, modalidad, cantidad):
    try:
        # Consultar el precio de la galleta desde la base de datos
        galleta_db = Galletas.query.filter_by(nombre=galleta).first()
        if not galleta_db:
            flash(f"No se encontró el precio para {galleta}", "error")
            return 0
            
        precio = float(galleta_db.precioUnitario)
        cantidad = int(cantidad)
        
        if modalidad == "suelta":
            return precio * cantidad
        else:
            cantidad_galletas = CANTIDADES_MODALIDAD.get(modalidad, 0)
            return precio * cantidad_galletas * cantidad
    except Exception as e:
        print(f"Error al calcular subtotal: {e}")
        flash("Error al calcular el subtotal", "error")
        return 0



def guardar_ticket(ventas, total, fecha_venta=None):
    with open(TICKET_FILE, "w", encoding='utf-8') as f:
        f.write("=== TICKET DE VENTA ===\n")
        if fecha_venta:
            f.write(f"Fecha: {fecha_venta}\n")
        else:
            f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("-----------------------\n")
        for venta in ventas:
            f.write(f"{venta['galleta']}|{venta['modalidad']}|{venta['cantidad']}|{venta['subtotal']:.2f}\n")
        f.write("-----------------------\n")
        f.write(f"TOTAL: {total:.2f}\n")



@app.route("/ventas", methods=["GET", "POST"])
@login_required
@roles_required('Vendedor', 'Administrador')
def ventas():
    galletas = StockGalletas.query.filter(StockGalletas.cantidadPiezas > 0).with_entities(StockGalletas.nombreGalleta).all()
    galletas = [g[0] for g in galletas]
    
    form = VentaForm(request.form)
    ventas = leer_ventas()
    total = calcular_total()
    
    if request.method == "POST":
        if "agregar" in request.form:
            if not form.validate():
                return render_template("ventas.html", 
                                    form=form,
                                    galletas=galletas, 
                                    ventas=ventas, 
                                    total=total)
            
            galleta = request.form.get("galleta", "").strip()
            modalidad = request.form.get("modalidad", "").strip()
            cantidad = form.cantidad.data
            
            # Verificar stock disponible
            stock = StockGalletas.query.filter_by(nombreGalleta=galleta).first()
            if not stock:
                flash(f"No hay stock disponible para {galleta}", "error")
                return redirect(url_for("ventas"))
            
            # Calcular cantidad total de galletas requeridas
            if modalidad == "suelta":
                galletas_requeridas = cantidad
            else:
                galletas_por_paquete = CANTIDADES_MODALIDAD.get(modalidad, 0)
                galletas_requeridas = galletas_por_paquete * cantidad
            
            if stock.cantidadPiezas < galletas_requeridas:
                flash(f"No hay suficiente stock. Solo hay {stock.cantidadPiezas} galletas de {galleta} disponibles", "error")
                return redirect(url_for("ventas"))
            
            subtotal = calcular_subtotal(galleta, modalidad, cantidad)
            if subtotal <= 0:
                flash("Error al calcular el subtotal", "error")
                return redirect(url_for("ventas"))
            
            guardar_venta(galleta, modalidad, cantidad, subtotal)
            flash("Galleta agregada al pedido", "success")
            return redirect(url_for("ventas"))
        
        elif "eliminar" in request.form:
            eliminar_ultima_venta()
            flash("Última galleta eliminada", "info")
            return redirect(url_for("ventas"))
        
        elif "finalizar" in request.form:
            if not ventas:
                flash("No hay galletas en el pedido", "error")
                return redirect(url_for("ventas"))
            
            # Verificar stock nuevamente antes de finalizar
            for venta in ventas:
                stock = StockGalletas.query.filter_by(nombreGalleta=venta['galleta']).first()
                if not stock:
                    flash(f"No hay stock disponible para {venta['galleta']}", "error")
                    return redirect(url_for("ventas"))
                
                if venta['modalidad'] == "suelta":
                    galletas_requeridas = venta['cantidad']
                else:
                    galletas_por_paquete = CANTIDADES_MODALIDAD.get(venta['modalidad'], 0)
                    galletas_requeridas = galletas_por_paquete * venta['cantidad']
                
                if stock.cantidadPiezas < galletas_requeridas:
                    flash(f"No hay suficiente stock. Solo hay {stock.cantidadPiezas} galletas de {venta['galleta']} disponibles", "error")
                    return redirect(url_for("ventas"))
            
            total = calcular_total()
            fecha_venta = request.form.get("fecha_venta")
            guardar_ticket(ventas, total, fecha_venta)
            
            # Actualizar el stock en la base de datos
            for venta in ventas:
                stock = StockGalletas.query.filter_by(nombreGalleta=venta['galleta']).first()
                if venta['modalidad'] == "suelta":
                    stock.cantidadPiezas -= venta['cantidad']
                else:
                    galletas_por_paquete = CANTIDADES_MODALIDAD.get(venta['modalidad'], 0)
                    stock.cantidadPiezas -= galletas_por_paquete * venta['cantidad']
                db.session.commit()
            
            with open(VENTAS_FILE, "w", encoding='utf-8') as f:
                f.write("")
            
            flash(f"Venta finalizada. Total: ${total:.2f}", "success")
            return redirect(url_for("TicketVenta"))
    
    return render_template("ventas.html", 
                        form=form,
                        galletas=galletas, 
                        ventas=ventas, 
                        total=total)

@app.route("/ventas2")
@login_required
@roles_required('Vendedor', 'Administrador')
def TicketVenta():
    ventas = []
    total = 0.0
    
    if os.path.exists(TICKET_FILE):
        with open(TICKET_FILE, "r", encoding='utf-8') as f:
            lines = f.readlines()
            # Saltar las primeras 3 líneas (encabezado) y la penúltima (línea de guiones)
            for line in lines[3:-2]:
                line = line.strip()
                if line and "|" in line:
                    try:
                        galleta, modalidad, cantidad, subtotal = line.split("|")
                        ventas.append({
                            "galleta": galleta,
                            "modalidad": modalidad,
                            "cantidad": cantidad,
                            "subtotal": float(subtotal)
                        })
                    except Exception as e:
                        print(f"Error procesando línea del ticket: {line}. Error: {e}")
            
            # Obtener el total de la última línea
            if lines and "TOTAL:" in lines[-1]:
                try:
                    total = float(lines[-1].split(":")[1].strip())
                except Exception as e:
                    print(f"Error obteniendo total: {e}")
    
    return render_template("Ticket_venta.html", ventas=ventas, total=total)


@app.route('/guardar_venta', methods=['POST'])
@login_required
@roles_required('Vendedor', 'Administrador')
def guardar_venta_db():
    try:
        codigo_usuario = request.form.get('codigoUsuario')
        
        if not codigo_usuario:
            flash('Código de usuario requerido', 'error')
            return redirect(url_for('TicketVenta'))
        
        # Validar que el código de empleado existe y tiene rol de Vendedor o Administrador
        empleado = Usuario.query.filter_by(codigoUsuario=codigo_usuario).first()
        
        if not empleado:
            flash('Código de empleado no encontrado', 'error')
            return redirect(url_for('TicketVenta'))
            
        if empleado.rol not in ['Vendedor', 'Administrador']:
            flash('Solo vendedores y administradores pueden registrar ventas', 'error')
            return redirect(url_for('TicketVenta'))
        
        # Verificar estatus del empleado
        if empleado.estatus != 'Activo':
            flash('El empleado no está activo en el sistema', 'error')
            return redirect(url_for('TicketVenta'))

        # Leer el ticket actual
        ventas = []
        total = 0.0
        fecha_venta = None
        
        if not os.path.exists(TICKET_FILE):
            flash('No hay ticket para guardar', 'error')
            return redirect(url_for('TicketVenta'))
        
        with open(TICKET_FILE, "r", encoding='utf-8') as f:
            lines = f.readlines()
            # Obtener la fecha de la segunda línea
            if len(lines) >= 2 and lines[1].startswith("Fecha: "):
                fecha_str = lines[1][7:].strip()
                try:
                    fecha_venta = datetime.strptime(fecha_str, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    try:
                        fecha_venta = datetime.strptime(fecha_str, '%Y-%m-%d')
                    except ValueError:
                        fecha_venta = datetime.now()
            
            for line in lines[3:-2]:
                line = line.strip()
                if line and "|" in line:
                    try:
                        galleta, modalidad, cantidad, subtotal = line.split("|")
                        ventas.append({
                            'galleta': galleta,
                            'modalidad': modalidad,
                            'cantidad': int(cantidad),
                            'subtotal': float(subtotal)
                        })
                    except ValueError as e:
                        app.logger.error(f"Error al procesar línea del ticket: {line}. Error: {e}")
                        continue
            
            if lines and "TOTAL:" in lines[-1]:
                try:
                    total = float(lines[-1].split(":")[1].strip())
                except ValueError as e:
                    app.logger.error(f"Error al obtener total: {e}")
                    total = 0.0

        # Validar que hay ventas para registrar
        if not ventas:
            flash('No hay productos en la venta para registrar', 'error')
            return redirect(url_for('TicketVenta'))

        # Guardar en la base de datos
        nueva_venta = Venta(
            total=total,
            codigoUsuario=codigo_usuario,
            fechaVenta=fecha_venta if fecha_venta else datetime.now()
        )
        db.session.add(nueva_venta)
        db.session.flush()
        
        for item in ventas:
            galleta = Galletas.query.filter_by(nombre=item['galleta']).first()
            if galleta:
                detalle = DetalleVenta(
                    idVenta=nueva_venta.idVenta,
                    idGalleta=galleta.idGalleta,
                    Presentacion=item['modalidad'],
                    cantidad=item['cantidad'],
                    subtotal=item['subtotal']
                )
                db.session.add(detalle)
            else:
                app.logger.warning(f"Galleta no encontrada: {item['galleta']}")
                flash(f'Galleta {item["galleta"]} no encontrada en el sistema', 'warning')
        
        db.session.commit()
        
        # Limpiar el archivo ticket.txt después de guardar
        with open(TICKET_FILE, "w", encoding='utf-8') as f:
            f.write("")
        
        flash('Venta guardada correctamente', 'success')
        return redirect(url_for('ventas'))
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al guardar venta: {str(e)}")
        flash(f'Error al guardar la venta: {str(e)}', 'error')
        return redirect(url_for('TicketVenta'))

@app.route("/StockVentas")
@login_required
@roles_required('Vendedor', 'Administrador')
def StockVentas():
    # Obtener todos los registros de stock de galletas
    stock_galletas = StockGalletas.query.order_by(StockGalletas.nombreGalleta).all()
    
    # Calcular días restantes hasta caducidad
    hoy = date.today()
    for galleta in stock_galletas:
        dias_restantes = (galleta.fechaPreparacion + timedelta(days=14) - hoy).days
        galleta.dias_restantes = max(0, dias_restantes)  # No mostrar números negativos
    
    return render_template("StockVentas.html", stock_galletas=stock_galletas)

@app.route('/mostrar_formulario_mensaje')
@login_required
def mostrar_formulario_mensaje():
    # Obtener el stock de galletas para la tabla principal
    stock_galletas = StockGalletas.query.order_by(StockGalletas.nombreGalleta).all()
    hoy = date.today()
    for galleta in stock_galletas:
        dias_restantes = (galleta.fechaPreparacion + timedelta(days=14) - hoy).days
        galleta.dias_restantes = max(0, dias_restantes)
    
    form = MensajeForm()
    return render_template("StockVentas.html", 
                            stock_galletas=stock_galletas,
                            mostrar_modal_mensaje=True,
                            mensaje_form=form)

@app.route('/guardar_mensaje', methods=['POST'])
@login_required
def guardar_mensaje():
    form = MensajeForm()
    if form.validate_on_submit():
        mensaje = form.mensaje.data.strip()
        estado = "pendiente"
        
        # Guardar en archivo TXT con el formato solicitado
        with open(SOLICITUDES_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{mensaje}|{estado}\n")
        
        flash('Solicitud enviada a producción correctamente', 'success')
    else:
        flash('Error: El mensaje no puede estar vacío', 'danger')
    
    return redirect(url_for('StockVentas'))

@app.route('/mostrar_notificaciones')
@login_required
def mostrar_notificaciones():
    # Obtener el stock de galletas para la tabla principal
    stock_galletas = StockGalletas.query.order_by(StockGalletas.nombreGalleta).all()
    hoy = date.today()
    for galleta in stock_galletas:
        dias_restantes = (galleta.fechaPreparacion + timedelta(days=14) - hoy).days
        galleta.dias_restantes = max(0, dias_restantes)
    
    # Leer las solicitudes existentes
    solicitudes = []
    if os.path.exists(SOLICITUDES_FILE):
        with open(SOLICITUDES_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        mensaje, estado = line.split('|')
                        solicitudes.append({'mensaje': mensaje, 'estado': estado})
                    except:
                        continue
    
    return render_template("StockVentas.html", 
                        stock_galletas=stock_galletas,
                        mostrar_modal_notificaciones=True,
                        solicitudes=solicitudes)

#estas funciones hasta cancelar son del modulo listado de pedidos
@app.route("/pedidos", methods=['GET', 'POST'])
@login_required
@roles_required('Vendedor', 'Administrador')
def pedidos():
    busqueda_pedidos_form = BusquedaPedidosForm(request.args)
    
    # Validar el formulario
    if not busqueda_pedidos_form.validate():
        flash('Error en los criterios de búsqueda', 'danger')
        return redirect(url_for('pedidos'))
    
    search_query = busqueda_pedidos_form.search.data.strip() if busqueda_pedidos_form.search.data else ''
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Consulta base con protección contra inyección SQL
    pedidos_query = db.session.query(Pedido).join(Usuario).order_by(Pedido.fechaDeEntrega.asc())
    
    if search_query:
        search_filter = f"%{search_query}%"
        pedidos_query = pedidos_query.filter(
            (Usuario.nombreCompleto.ilike(search_filter)) |
            (Pedido.estado.ilike(search_filter))
        )
    
    pedidos_paginados = pedidos_query.paginate(page=page, per_page=per_page)
    
    return render_template("pedidosVentas.html", 
                        pedidos_paginados=pedidos_paginados,
                        busqueda_pedidos_form=busqueda_pedidos_form,
                        search_query=search_query)

@app.route("/detalle_pedido/<int:id_pedido>")
@login_required
@roles_required('Vendedor', 'Administrador')
def detalle_pedido(id_pedido):
    pedido_actual = Pedido.query.get_or_404(id_pedido)
    detalles_pedido = DetallePedido.query.filter_by(idPedido=id_pedido).all()
    
    return render_template("pedidosVentas.html",
                        mostrar_modal_detalle=True,
                        pedido_actual=pedido_actual,
                        detalles_pedido=detalles_pedido,
                        pedidos_paginados=Pedido.query.paginate(page=1, per_page=10),
                        search_query='')

@app.route("/mostrar_confirmacion_entregar/<int:id_pedido>")
@login_required
@roles_required('Vendedor', 'Administrador')
def mostrar_confirmacion_entregar(id_pedido):
    pedido_actual = Pedido.query.get_or_404(id_pedido)
    resto_pagar = pedido_actual.totalApagar - pedido_actual.anticipo
    
    return render_template("pedidosVentas.html",
                        mostrar_modal_detalle=True,
                        mostrar_modal_confirmar_entrega=True,
                        pedido_actual=pedido_actual,
                        resto_pagar=resto_pagar,
                        detalles_pedido=DetallePedido.query.filter_by(idPedido=id_pedido).all(),
                        pedidos_paginados=Pedido.query.paginate(page=1, per_page=10),
                        search_query='')

@app.route("/mostrar_confirmacion_cancelar/<int:id_pedido>")
@login_required
@roles_required('Vendedor', 'Administrador')
def mostrar_confirmacion_cancelar(id_pedido):
    pedido_actual = Pedido.query.get_or_404(id_pedido)
    
    return render_template("pedidosVentas.html",
                        mostrar_modal_detalle=True,
                        mostrar_modal_confirmar_cancelar=True,
                        pedido_actual=pedido_actual,
                        detalles_pedido=DetallePedido.query.filter_by(idPedido=id_pedido).all(),
                        pedidos_paginados=Pedido.query.paginate(page=1, per_page=10),
                        search_query='')

@app.route("/entregar_pedido/<int:id_pedido>", methods=['POST'])
@login_required
@roles_required('Vendedor', 'Administrador')
def entregar_pedido(id_pedido):
    try:
        # Validación de empleado (se mantiene igual)
        codigo_empleado = request.form.get("codigo_empleado", "").strip()
        if not codigo_empleado:
            flash("Para completar la entrega debes ingresar tu código de empleado", "error")
            return redirect(url_for('detalle_pedido', id_pedido=id_pedido))
        
        empleado = Usuario.query.filter_by(codigoUsuario=codigo_empleado, rol='Vendedor', estatus='Activo').first()
        if not empleado:
            flash("Código de empleado no válido o no tienes permiso para realizar entregas", "error")
            return redirect(url_for('detalle_pedido', id_pedido=id_pedido))

        pedido = Pedido.query.get_or_404(id_pedido)
        
        if pedido.estado == 'Completado':
            flash("Este pedido ya ha sido completado anteriormente", "warning")
            return redirect(url_for('detalle_pedido', id_pedido=id_pedido))

        pedido.estado = 'Completado'
        detalles = DetallePedido.query.filter_by(idPedido=id_pedido).all()
        
        venta = Venta(
            total=pedido.totalApagar,
            codigoUsuario=codigo_empleado,
            fechaVenta=datetime.now()
        )
        db.session.add(venta)
        db.session.flush()

        # Calcular subtotales para detalleVenta
        for detalle in detalles:
            # Calcular subtotal exacto para detalleVenta
            precio_galleta = PRECIOS_GALLETAS.get(detalle.galleta.nombre, 0)
            
            if detalle.Presentacion == "suelta":
                subtotal = precio_galleta * detalle.cantidad
            else:
                cantidad_galletas = CANTIDADES_MODALIDAD.get(detalle.Presentacion, 1)
                subtotal = precio_galleta * cantidad_galletas * detalle.cantidad
            
            # Registrar en detalleVenta
            detalle_venta = DetalleVenta(
                idVenta=venta.idVenta,
                idGalleta=detalle.idGalleta,
                Presentacion=detalle.Presentacion,
                cantidad=detalle.cantidad,
                subtotal=subtotal  # Este es el valor exacto para la venta
            )
            db.session.add(detalle_venta)
            
            # Actualizar resto a pagar en detallePedido (si es necesario)
            detalle.restoApagar = 0.00
            
            # Manejo del stock
            if detalle.Presentacion == "suelta":
                galletas_a_descontar = detalle.cantidad
            else:
                galletas_por_presentacion = CANTIDADES_MODALIDAD.get(detalle.Presentacion, 1)
                galletas_a_descontar = detalle.cantidad * galletas_por_presentacion
            
            stock_galleta = StockGalletas.query.filter_by(
                nombreGalleta=detalle.galleta.nombre
            ).order_by(StockGalletas.fechaPreparacion.asc()).first()
            
            if stock_galleta:
                if stock_galleta.cantidadPiezas < galletas_a_descontar:
                    db.session.rollback()
                    flash(f'No hay suficiente stock de {detalle.galleta.nombre}. Stock disponible: {stock_galleta.cantidadPiezas}, se necesitan: {galletas_a_descontar}', 'danger')
                    return redirect(url_for('detalle_pedido', id_pedido=id_pedido))
                stock_galleta.cantidadPiezas -= galletas_a_descontar
        
        db.session.commit()
        flash('Pedido completado y venta registrada correctamente', 'success')
        return redirect(url_for('pedidos'))
    
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error al completar pedido: {str(e)}")
        flash(f'Error al completar el pedido: {str(e)}', 'danger')
        return redirect(url_for('detalle_pedido', id_pedido=id_pedido))
    

@app.route("/cancelar_pedido/<int:id_pedido>", methods=['POST'])
@login_required
@roles_required('Vendedor', 'Administrador')
def cancelar_pedido(id_pedido):
    pedido = Pedido.query.get_or_404(id_pedido)
    pedido.estado = 'Cancelado'
    db.session.commit()
    flash('Pedido cancelado correctamente', 'success')
    return redirect(url_for('pedidos'))
    
#esta funcion pertenece al modulo de listado y corte de ventas 
@app.route("/listado", methods=['GET', 'POST'])
@login_required
@roles_required('Vendedor', 'Administrador')
def listado():
    # Crear formulario de búsqueda
    busqueda_form = BusquedaForm(request.args)
    
    # Validar y sanitizar búsqueda
    search_query = ''
    if busqueda_form.validate():
        search_query = busqueda_form.busqueda.data.strip() if busqueda_form.busqueda.data else ''
    
    # Consulta base para ventas
    ventas_query = Venta.query.order_by(Venta.fechaVenta.desc())
    
    # Filtrar por búsqueda si existe
    if search_query:
        ventas_query = ventas_query.filter(
            (Venta.codigoUsuario.ilike(f'%{search_query}%')) |  # ilike para case-insensitive
            (Venta.total.cast(db.String).ilike(f'%{search_query}%'))
        )
    
    ventas = ventas_query.all()
    
    # Procesar corte de ventas
    total_ventas = 0
    corte_realizado = False
    mensaje_corte = ""
    
    if request.method == 'POST' and 'buscar_ventas' in request.form:
        tipo_fecha = request.form.get('tipo_fecha')
        corte_realizado = True
        
        if tipo_fecha == 'dia':
            # Corte del día actual
            hoy = date.today()
            ventas_corte = Venta.query.filter(
                func.date(Venta.fechaVenta) == hoy
            ).all()
            total_ventas = sum(v.total for v in ventas_corte)
            mensaje_corte = f"Corte del día {hoy.strftime('%d/%m/%Y')}"
            
        elif tipo_fecha == 'mes':
            # Corte por mes
            mes = request.form.get('mes', str(datetime.now().month))
            if mes.isdigit() and 1 <= int(mes) <= 12:
                mes = int(mes)
                ventas_corte = Venta.query.filter(
                    extract('month', Venta.fechaVenta) == mes
                ).all()
                total_ventas = sum(v.total for v in ventas_corte)
                mensaje_corte = f"Corte del mes {mes}"
            else:
                flash("Mes inválido. Debe ser un número entre 1 y 12", "error")
                
        elif tipo_fecha == 'fecha':
            # Corte por fecha específica
            fecha_str = request.form.get('fecha')
            if fecha_str:
                try:
                    fecha = datetime.strptime(fecha_str, '%Y-%m-%d').date()
                    ventas_corte = Venta.query.filter(
                        func.date(Venta.fechaVenta) == fecha
                    ).all()
                    total_ventas = sum(v.total for v in ventas_corte)
                    mensaje_corte = f"Corte del día {fecha.strftime('%d/%m/%Y')}"
                except ValueError:
                    flash("Formato de fecha inválido", "error")
    
    return render_template("listadoCorte.html", 
                            ventas=ventas, 
                            total_ventas=total_ventas,
                            busqueda_form=busqueda_form,
                            corte_realizado=corte_realizado,
                            mensaje_corte=mensaje_corte)

@app.route("/detalle_venta/<int:id_venta>")
@login_required
@roles_required('Vendedor', 'Administrador')
def detalle_venta(id_venta):
    venta = Venta.query.get_or_404(id_venta)
    detalles = DetalleVenta.query.filter_by(idVenta=id_venta).join(Galletas).all()
    
    return jsonify({
        'venta': {
            'id': venta.idVenta,
            'fecha': venta.fechaVenta.strftime('%Y-%m-%d %H:%M:%S'),
            'total': float(venta.total),
            'usuario': venta.codigoUsuario
        },
        'detalles': [{
            'galleta': detalle.galleta.nombre,
            'presentacion': detalle.Presentacion,
            'cantidad': detalle.cantidad,
            'subtotal': float(detalle.subtotal)
        } for detalle in detalles]
    })
    
@app.route('/')
@login_required
def welcome():
    return render_template('welcome.html')

#con esta funcion el vendedor puede levantar un pedido como cliente 
@app.route("/pedidoVentas", methods=["GET", "POST"])
@login_required
@roles_required('Vendedor', 'Administrador')
def pedido_ventas():
    galletas = Galletas.query.with_entities(Galletas.nombre).all()
    galletas = [g[0] for g in galletas]
    usuarios = Usuario.query.filter_by(estatus='Activo', rol='Cliente').all()
    
    form = PedidoForm()
    carrito = leer_pedidos()
    total = calcular_total_pedido()
    
    if request.method == "POST":
        if "agregar" in request.form:
            form = PedidoForm(request.form)
            
            if form.validate():
                galleta = request.form.get("galleta", "").strip()
                modalidad = request.form.get("modalidad", "").strip()
                cantidad = form.cantidad.data
        
                subtotal = calcular_subtotal(galleta, modalidad, cantidad)
                if subtotal > 0:
                    guardar_pedido(galleta, modalidad, cantidad, subtotal)
                    flash("Galleta agregada al pedido", "success")
                    return redirect(url_for("pedido_ventas"))  
                else:
                    flash("Error al calcular el subtotal", "error")
            
        elif "eliminarGalleta" in request.form:
            eliminar_ultimo_pedido()
            flash("Última galleta eliminada del pedido", "info")
            return redirect(url_for("pedido_ventas"))
        
        elif "finalizarPedido" in request.form:
            if not carrito:
                flash("No hay galletas en el pedido", "error")
                return redirect(url_for("pedido_ventas"))
            
            usuario_id = request.form.get("usuario_id", type=int)
            if usuario_id is None:
                flash("Por favor, selecciona un usuario válido", "error")
                return redirect(url_for("pedido_ventas"))
            
            usuario = Usuario.query.get(usuario_id)
            if not usuario:
                flash("Usuario no encontrado", "error")
                return redirect(url_for("pedido_ventas"))
            
            fecha_entrega = request.form.get("fecha_entrega", "")
            try:
                anticipo = float(request.form.get("anticipo", 0))
                if anticipo < 0:
                    flash("El anticipo no puede ser un número negativo", "error")
                    return redirect(url_for("pedido_ventas"))
            except ValueError:
                flash("El anticipo debe ser un valor numérico válido", "error")
                return redirect(url_for("pedido_ventas"))
            
            try:
                fecha_entrega_obj = datetime.strptime(fecha_entrega, '%Y-%m-%d').date()
                if fecha_entrega_obj < date.today():
                    flash("La fecha de entrega no puede ser anterior a hoy", "error")
                    return redirect(url_for("pedido_ventas"))
            except ValueError:
                flash("Fecha de entrega inválida", "error")
                return redirect(url_for("pedido_ventas"))
            
            total_pedido = calcular_total_pedido()
            if anticipo > total_pedido:
                flash("El anticipo no puede ser mayor al total del pedido", "error")
                return redirect(url_for("pedido_ventas"))
            
            resto_a_pagar = total_pedido - anticipo
            
            pedido = Pedido(
                idUsuario=usuario.idUsuario,
                fechaApartado=datetime.now(),
                fechaDeEntrega=fecha_entrega_obj,
                anticipo=anticipo,
                totalApagar=total_pedido,
                estado='Pendiente'
            )
            
            db.session.add(pedido)
            db.session.flush()
            
            resto_a_pagar_por_detalle = resto_a_pagar / len(carrito) if carrito else 0
            
            for item in carrito:
                galleta_db = Galletas.query.filter_by(nombre=item["galleta"]).first()
                if not galleta_db:
                    db.session.rollback()
                    flash(f"Galleta {item['galleta']} no encontrada", "error")
                    return redirect(url_for("pedido_ventas"))
                
                detalle = DetallePedido(
                    idPedido=pedido.idPedido,
                    idGalleta=galleta_db.idGalleta,
                    Presentacion=item["modalidad"],
                    cantidad=item["cantidad"],
                    restoApagar=resto_a_pagar_por_detalle
                )
                db.session.add(detalle)
            
            db.session.commit()
            
            with open(PEDIDOS_FILE, "w", encoding='utf-8') as f:
                f.write("")
            
            flash("Pedido realizado con éxito", "success")
            return redirect(url_for("pedido_ventas"))
    
    return render_template("pedidos.html",
                                form=form,
                                galletas=galletas,
                                usuarios=usuarios,
                                carrito=carrito,
                                total=total)



if __name__ == '__main__':
    csrf.init_app(app)
    db.init_app(app)
    app.run(debug=True)
