from wtforms import Form, StringField, IntegerField, validators, HiddenField
from flask_wtf.file import FileField, FileAllowed
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length, NumberRange
from wtforms import SelectField, DecimalField,  DateField

class FormularioMermas(FlaskForm):
    tipoMerma = SelectField(
        'Tipo de Merma',
        choices=[],
        validators=[DataRequired(message='Selecciona un tipo de merma')]
    )
    lote = SelectField(
        'Lote',
        choices=[],
        validators=[DataRequired()]
    )
    cantidadDisponible = DecimalField(
        'Cantidad Disponible',
        render_kw={'readonly': True}
    )
    cantidadMerma = DecimalField(
        'Cantidad Desperdiciada',
        validators=[
            DataRequired(message='La cantidad es obligatoria'), 
            NumberRange(min=0.01, message='La cantidad debe ser positiva')
        ],
        render_kw={'step': '0.01', 'min': '0.01'}
    )
    fechaMerma = DateField(
        'Fecha de Merma',
        validators=[DataRequired(message='La fecha de merma es obligatoria')]
    )



class TablaProduccion(Form):
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



class FormularioRecetas(FlaskForm):
    nombreGalleta = StringField('Nombre de la Galleta', [
        DataRequired(),
        Length(min=4, max=255)
    ])
    procedimiento = StringField('Procedimiento', [
        DataRequired()
    ])
    imagen = FileField('Imagen (opcional)', [
        FileAllowed(['jpg', 'png', 'jpeg'], 'Solo se permiten imágenes con formato JPG, JPEG o PNG')
    ])