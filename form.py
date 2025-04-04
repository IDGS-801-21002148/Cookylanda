from wtforms import Form, StringField, IntegerField, SelectField, validators, DateField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, NumberRange,  InputRequired, Regexp,Optional
from flask_wtf import FlaskForm


class VentaForm(Form):
    
    
    cantidad = IntegerField(
        'Cantidad',
        validators=[InputRequired(message="Este campo es requerido")]
    )
    fecha_venta = DateField(
        'Fecha de Venta',
        validators=[Optional()],  # Hacemos que la fecha sea opcional
        format='%Y-%m-%d'
    )

class BusquedaForm(Form):
    busqueda = StringField(
        'Buscar',
        validators=[
            Regexp(r'^[a-zA-Z0-9 ]*$', message="Solo se permiten letras, números y espacios")
        ]
    )

class MensajeForm(FlaskForm):
    mensaje = TextAreaField('Mensaje', validators=[DataRequired()])
    submit = SubmitField('Enviar')

class BusquedaPedidosForm(Form):
    search = StringField(
        'Buscar',
        validators=[
            Regexp(r'^[a-zA-Z0-9 áéíóúÁÉÍÓÚñÑ\-]*$', 
                    message="Solo se permiten letras, números, espacios y guiones")
        ]
    )

class PedidoForm(FlaskForm): 
    cantidad = IntegerField(
        'Cantidad para Pedido',
        validators=[
            InputRequired(message="La cantidad es requerida"),
        ]
    )