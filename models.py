from flask_sqlalchemy import SQLAlchemy

import datetime

db = SQLAlchemy()

class Usuario(db.Model):
    __tablename__ = 'usuario'
    idUsuario = db.Column(db.Integer, primary_key=True)
    nombreCompleto = db.Column(db.String(255), nullable=False)
    apePaterno = db.Column(db.String(255), nullable=False)
    apeMaterno = db.Column(db.String(255), nullable=False)
    usuario = db.Column(db.String(255), nullable=False, unique=True)
    contrasenia = db.Column(db.String(255), nullable=False)
    correo = db.Column(db.String(255), nullable=False, unique=True)
    rol = db.Column(db.Enum('Administrador', 'Cliente', 'Vendedor', 'Cocinero'), nullable=False)
    estatus = db.Column(db.Enum('Activo', 'Inactivo'), nullable=False, default='Activo')
    codigoUsuario = db.Column(db.String(255), unique=True)

class Galletas(db.Model):
    __tablename__ = 'galletas'
    idGalleta = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False)
    descripcion = db.Column(db.Text)
    precioUnitario = db.Column(db.Numeric(10, 2), nullable=False)

class StockGalletas(db.Model):
    __tablename__ = 'stockGalletas'
    idStock = db.Column(db.Integer, primary_key=True)
    nombreGalleta = db.Column(db.String(255), nullable=False)
    cantidadPiezas = db.Column(db.Integer, nullable=False, default=0)
    fechaPreparacion = db.Column(db.Date, nullable=False)

class Venta(db.Model):
    __tablename__ = 'venta'
    idVenta = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fechaVenta = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
    total = db.Column(db.Numeric(10, 2), nullable=False)
    codigoUsuario = db.Column(db.String(255))

class DetalleVenta(db.Model):
    __tablename__ = 'detalleVenta'
    idDetalle = db.Column(db.Integer, primary_key=True, autoincrement=True)
    idVenta = db.Column(db.Integer, db.ForeignKey('venta.idVenta', ondelete='CASCADE'), nullable=False)
    idGalleta = db.Column(db.Integer, db.ForeignKey('galletas.idGalleta', ondelete='CASCADE'), nullable=False)
    Presentacion = db.Column(db.String(100))
    cantidad = db.Column(db.Integer, nullable=False)
    subtotal = db.Column(db.Numeric(10, 2), nullable=False)
    
    venta = db.relationship('Venta', backref='detalles')
    galleta = db.relationship('Galletas')


class Pedido(db.Model):
    __tablename__ = 'pedido'
    idPedido = db.Column(db.Integer, primary_key=True)
    idUsuario = db.Column(db.Integer, db.ForeignKey('usuario.idUsuario'), nullable=False)
    fechaApartado = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
    fechaDeEntrega = db.Column(db.Date, nullable=False)
    estado = db.Column(db.Enum('Pendiente', 'Completado', 'Cancelado'), nullable=False, default='Pendiente')
    anticipo = db.Column(db.Numeric(10, 2), nullable=False)
    totalApagar = db.Column(db.Numeric(10, 2), nullable=False)
    
    usuario = db.relationship('Usuario')

class DetallePedido(db.Model):
    __tablename__ = 'detallePedido'
    idDetalle = db.Column(db.Integer, primary_key=True)
    idPedido = db.Column(db.Integer, db.ForeignKey('pedido.idPedido'), nullable=False)
    idGalleta = db.Column(db.Integer, db.ForeignKey('galletas.idGalleta'), nullable=False)
    Presentacion = db.Column(db.String(100), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    restoApagar = db.Column(db.Numeric(10, 2), default=0)
    
    pedido = db.relationship('Pedido')
    galleta = db.relationship('Galletas')