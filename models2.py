from flask_sqlalchemy import SQLAlchemy

import datetime

from sqlalchemy import JSON, text


from sqlalchemy.dialects.mysql import JSON


db = SQLAlchemy()

class Receta(db.Model):
    __tablename__ = 'receta'
    
    idReceta = db.Column(db.Integer, primary_key=True)
    nombreGalleta = db.Column(db.String(255), nullable=False)

    # Ingredientes base
    harIng = db.Column(db.String(255), default='Harina', nullable=False)
    cantHar = db.Column(db.Numeric(6,2))
    harUdad = db.Column(db.String(255), nullable=False)

    manIng = db.Column(db.String(255), default='Mantequilla', nullable=False)
    cantMan = db.Column(db.Numeric(6,2))
    manUdad = db.Column(db.String(255), nullable=False)

    azurIng = db.Column(db.String(255), default='Azúcar', nullable=False)
    cantAzur = db.Column(db.Numeric(6,2))
    azurUdad = db.Column(db.String(255), nullable=False)

    huvrIng = db.Column(db.String(255), default='Huevo', nullable=False)
    cantHuv = db.Column(db.Numeric(6,2))
    huvUdad = db.Column(db.String(255), nullable=False)

    horIng = db.Column(db.String(255), default='Polvo de Hornear', nullable=False)
    cantHor = db.Column(db.Numeric(6,2))
    horUdad = db.Column(db.String(255), nullable=False)

    salIng = db.Column(db.String(255), default='Sal', nullable=False)
    cantSal = db.Column(db.Numeric(6,2))
    salUdad = db.Column(db.String(255), nullable=False)

    LechIng = db.Column(db.String(255), default='Leche', nullable=False)
    cantLech = db.Column(db.Numeric(6,2))
    lechUdad = db.Column(db.String(255), nullable=False)

    # Ingredientes adicionales (almacenados como JSON)
    adicional = db.Column(JSON, nullable=False, default=list)
    cantAdicional = db.Column(JSON, nullable=False, default=list)
    unidad = db.Column(JSON, nullable=False, default=list)

    procedimiento = db.Column(db.Text, nullable=False)
    imagen = db.Column(db.Text)
    estatus = db.Column(db.Enum('Activo', 'Inactivo'), default='Activo', nullable=False)
    codigoUsuario = db.Column(db.String(255))

# -----------------------------------------ROCHA--------------------------------------------------------------------------------------------


class Merma(db.Model):
    __tablename__ = "merma"
    
    idMerma = db.Column(db.Integer, primary_key=True, autoincrement=True)
    tipoMerma = db.Column(db.Enum(
       'Caducidad Materia Prima' ,'Caducidad Materia Prima', 'Caducidad Galletas', 'Quemado', 'Galletas rotas', 'Pérdidas por manipulación'
    ), nullable=False)
    idInventario = db.Column(db.Integer, nullable=True)
    cantidadMerma = db.Column(db.Numeric(10, 2), nullable=False)
    fechaMerma = db.Column(db.DateTime, default=db.func.current_timestamp())
    lote = db.Column(db.String(50), nullable=True)
    producto = db.Column(db.String(200), nullable=False)
    codigoUsuario = db.Column(db.String(255), nullable=False)

# ------------------------------------------JUAN ------------------------------------------------------------------------------------------------------

class Producto(db.Model):
    __tablename__ = 'producto'
    
    idProducto = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(150), nullable=False)
    precio = db.Column(db.Float, nullable=False)
    idProveedor = db.Column(db.Integer, db.ForeignKey('proveedor.idProveedor'), nullable=False)
    estatus = db.Column(db.Enum('Activo', 'Inactivo', name='estatus_enum'), nullable=False, default='Activo')
    
    # Relación con Proveedor
    proveedor = db.relationship('Proveedor', backref=db.backref('productos', lazy=True))

# Asegúrate de que tu modelo Proveedor tenga la relación inversa (ya está en el backref)

class Proveedor(db.Model):
    __tablename__ = 'proveedor'

    idProveedor = db.Column(db.Integer, primary_key=True)
    nombreProveedor = db.Column(db.String(150), nullable=False)
    direccion = db.Column(db.String(255), nullable=True)
    telefono = db.Column(db.String(15), nullable=True)
    correo = db.Column(db.String(100), nullable=True)
    fechaRegistro = db.Column(db.DateTime, default=datetime.datetime.now)
    tipoVendedor = db.Column(db.Enum('Principal', 'Secundario', name='tipo_vendedor_enum'), nullable=False)
    empresa = db.Column(db.String(150), nullable=False)
    estatus = db.Column(db.Enum('Activo', 'Inactivo', name='estatus_enum'), nullable=False, default='Activo')
    codigoUsuario = db.Column(db.String(255), nullable=True)

class Materia(db.Model):
    __tablename__ = 'materia'

    idProducto = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nombreProducto = db.Column(db.String(200), nullable=False, unique=True)
    cantidad = db.Column(db.Numeric(10, 3), nullable=False)
    fechaCompra = db.Column(db.Date, nullable=False)

class Compra(db.Model):
    __tablename__ = 'compra'

    idCompra = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fechaCompra = db.Column(db.DateTime, default=datetime.datetime.now, nullable=False)
    proveedor = db.Column(db.Integer, db.ForeignKey('proveedor.idProveedor'), nullable=False)
    total = db.Column(db.Numeric(10, 2), nullable=False)
    estatus = db.Column(db.Enum('activo', 'inactivo', name='estatus_enum'), nullable=False, default='activo')
    codigoUsuario = db.Column(db.String(255), nullable=True)

    proveedor_relacion = db.relationship('Proveedor', backref='compras')

class DetalleCompra(db.Model):
    __tablename__ = 'detalleCompra'

    idDetalle = db.Column(db.Integer, primary_key=True, autoincrement=True)
    idCompra = db.Column(db.Integer, db.ForeignKey('compra.idCompra'), nullable=False)
    nombreProducto = db.Column(db.String(200), nullable=False)
    presentacion = db.Column(db.String(100), nullable=False)
    cantidad = db.Column(db.Numeric(10, 2), nullable=False)

    compra_relacion = db.relationship('Compra', backref='detalles')

    def to_dict(self):
        return {
            "idDetalle": self.idDetalle,  # Corregido: usar idDetalle en lugar de idDetalleCompra
            "idCompra": self.idCompra,
            "nombreProducto": self.nombreProducto,
            "cantidad": float(self.cantidad),  # Convertir Decimal a float
            "presentacion": self.presentacion
        }

#ROCHA--------------------------------------
class CantidadGalletas(db.Model):
    __tablename__ = "stockGalletas"

    idStock = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nombreGalleta = db.Column(db.String(255), nullable=False)
    cantidadPiezas = db.Column(db.Integer, nullable=False, default=0)
    fechaPreparacion = db.Column(db.Date, nullable=False)
    fechaCaducidad = db.Column(db.Date, nullable=False)

class StockGalletas(db.Model):
    __tablename__ = "stockGalletas"
    idStock = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nombreGalleta = db.Column(db.String(255), nullable=False)
    cantidadPiezas = db.Column(db.Integer, nullable=False, default=0)
    fechaPreparacion = db.Column(db.Date, nullable=False)
    fechaCaducidad = db.Column(
        db.Date, 
        nullable=False,
        server_default=text("(fechaPreparacion + INTERVAL 14 DAY)"),  # Para MySQL
        server_onupdate=text("(fechaPreparacion + INTERVAL 14 DAY)")  # Opcional
    )

    __table_args__ = {"extend_existing": True}


# ----------------------------------------------YOLANDA ----------------------------------------------------------------------------------


class Galletas(db.Model):
    __tablename__ = 'galletas'
    idGalleta = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False)
    descripcion = db.Column(db.Text)
    precioUnitario = db.Column(db.Numeric(10, 2), nullable=False)


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
    
    #usuario = db.relationship('usuario')

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

