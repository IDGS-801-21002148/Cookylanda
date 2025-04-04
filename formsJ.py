from flask_wtf import FlaskForm
from wtforms import DateField, DecimalField, FieldList, FileField, Form, FormField, HiddenField, IntegerField, StringField, SelectField, SubmitField, TelField, TextAreaField, validators
from wtforms.validators import DataRequired, Length, Email, Regexp, NumberRange, InputRequired
import re
from flask_wtf.file import FileField, FileAllowed

class ProductoForm(FlaskForm):
    nombre = StringField('Nombre del Producto', validators=[DataRequired()])
    precio = StringField('Precio', validators=[DataRequired()])

class ProveedorForm(FlaskForm):
    def sanitize_string(value):
        """ Elimina espacios extra y caracteres no deseados """
        if value:
            value = value.strip()  # Quita espacios en los extremos
            value = re.sub(r'[<>]', '', value)  # Evita etiquetas HTML/JS
        return value
    
    nombre = StringField("Nombre", validators=[
        DataRequired(message="El nombre es obligatorio"),
        Length(min=3, max=150, message="Debe tener entre 3 y 150 caracteres")
    ])
    
    direccion = StringField("Dirección", validators=[
        DataRequired(message="La dirección es obligatoria"),
        Length(max=255, message="Máximo 255 caracteres")
    ])
    
    telefono = TelField("Teléfono", validators=[
        DataRequired(message="El teléfono es obligatorio"),
        Regexp(r'^\d{10}$', message="Debe contener exactamente 10 dígitos numéricos")
    ])
    
    correo = StringField("Correo", validators=[
        DataRequired(message="El correo es obligatorio"),
        Email(message="Formato de correo inválido")
    ])
    
    vendedor = SelectField("Vendedor", choices=[("Principal", "Principal"), ("Secundario", "Secundario")], validators=[
        DataRequired(message="Debe seleccionar un tipo de vendedor")
    ])
    
    empresa = StringField("Empresa", validators=[
        DataRequired(message="La empresa es obligatoria"),
        Length(max=150, message="Máximo 150 caracteres")
    ])
    productos = FieldList(FormField(ProductoForm), min_entries=1)

    
    def process_formdata(self, valuelist):
        """ Sanitiza todos los campos antes de validarlos """
        if valuelist:
            self.data = self.sanitize_string(valuelist[0])


    submit_agregar = SubmitField("Agregar")
    submit_modificar = SubmitField("Modificar")
    submit_eliminar = SubmitField("Eliminar")

class MateriaForm(FlaskForm):
    nombreProducto = StringField('Nombre del Producto', validators=[DataRequired(), Length(max=200)])
    cantidad = DecimalField('Cantidad', validators=[DataRequired(), NumberRange(min=0)])

class CompraForm(FlaskForm):
    proveedor = IntegerField('ID del Proveedor', validators=[DataRequired()])
    total = DecimalField('Total', validators=[DataRequired(), NumberRange(min=0)])
    codigoUsuario = StringField('Código de Usuario', validators=[DataRequired(), Length(max=50)])  # Agregar esto


class DetalleCompraForm(FlaskForm):
    idCompra = IntegerField('ID de la Compra')  # Agregar esto para relacionarlo
    nombreProducto = StringField('Nombre del Producto', validators=[DataRequired(), Length(max=200)])
    presentacion = StringField('Presentación', validators=[DataRequired(), Length(max=100)])
    cantidad = DecimalField('Cantidad', validators=[DataRequired(), NumberRange(min=0)])

#ROCHA ---------------------------------class TablaProduccion(Form):
    nombreGalleta = StringField('Nombre de la Galleta', [
        validators.DataRequired(message='El nombre es obligatorio'),
        validators.Length(min=4, max=255, message='El nombre debe tener entre 4 y 255 caracteres')
    ])
    cantidad = IntegerField('Cantidad de Galletas', [
        validators.DataRequired(message='La cantidad es obligatoria'),
        validators.NumberRange(min=1, message='Debe haber al menos 1 galleta')
    ])
    proceso = StringField('Proceso', [
        validators.DataRequired(message='El proceso es obligatorio'),
        validators.Length(min=4, max=255, message='El proceso debe tener entre 4 y 255 caracteres')
    ])



class FormularioNotificaciones(Form):
    mensaje = StringField('Mensaje', [
        validators.DataRequired(message='El mensaje es obligatorio'),
        validators.Length(min=5, max=255, message='El mensaje debe tener entre 5 y 255 caracteres')
    ])
    id_mensaje = HiddenField('ID del Mensaje')




class FormularioNotificacion(Form):
    nombreGalleta = StringField('Nombre de la Galleta', [
        validators.DataRequired(message='El nombre es obligatorio'),
        validators.Length(min=4, max=255, message='El nombre debe tener entre 4 y 255 caracteres')
    ])
    cantidad = IntegerField('Cantidad de Galletas', [
        validators.DataRequired(message='La cantidad es obligatoria'),
        validators.NumberRange(min=1, message='Debe haber al menos 1 galleta')
    ])
    id_mensaje = HiddenField('ID del Mensaje')
