from wtforms import Form, StringField, TextAreaField, SelectField, FileField
from wtforms.validators import DataRequired, Length, Regexp
from flask_wtf import FlaskForm


# Expresiones regulares para validación
solo_letras = Regexp(r'^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]+$', message="Solo se permiten letras y espacios")
caracteres_permitidos = Regexp(r'^[a-zA-Z0-9.,\s]+$', message="Solo se permiten números, letras, puntos y comas")

class RecetaForm(FlaskForm):
   

    nombreGalleta = StringField('Nombre de la Galleta', validators=[
        DataRequired(), 
        solo_letras,
        Length(max=255)
        ])


     # Campo de Harina
    cmbHarina = SelectField('Ingrediente 1', choices=[('Harina', 'Harina')], validators=[
        DataRequired(),
        solo_letras])

    cantHar = StringField('Cantidad', validators=[
        DataRequired(), 
        caracteres_permitidos,
        Length(max=255)
        ])


    cmbHarinaUnidad = SelectField('Unidades:', choices=[('Gramos', 'Gramos'), ('Kilo', 'Kilo') ], validators=[
        DataRequired(),
        solo_letras, 
        Length(max=255)
        ])


    # Campo de Mantequilla
    cmbMantequilla = SelectField('Ingrediente 2', choices=[('Mantequilla', 'Mantequilla')], validators=[
        DataRequired(),
        solo_letras])

    cantMan = StringField('Cantidad ', validators=[
        DataRequired(), 
        caracteres_permitidos,
        Length(max=255)
        ])

    cmbMantUnidad = SelectField('Unidad:', choices=[('Gramos', 'Gramos'), ('Kilo', 'Kilo')], validators=[
        DataRequired(),
        solo_letras])




    # Campo de Azúcar
    cmbAzucar = SelectField('Ingrediente 3', choices=[('Azúcar', 'Azúcar')], validators=[
        DataRequired(),
        solo_letras
        ])

    cantAzur = StringField('Cantidad', validators=[
        DataRequired(), 
        caracteres_permitidos,
        Length(max=255)
        ])


    cmbAzurUnidad = SelectField('Unidades:', choices=[('Gramos', 'Gramos'), ('Kilos', 'Kilos')], validators=[
        DataRequired(),
        solo_letras, 
        Length(max=255)
        ])


    


    # Campo de Huevo
    cmbHuevo = SelectField('Ingrediente 4', choices=[('Huevo', 'Huevo')], validators=[
        DataRequired(),
        solo_letras])


    cantHuv = StringField('Cantidad ', validators=[
        DataRequired(), 
        caracteres_permitidos,
        Length(max=255)
        ])


    cmbHuevUnidad = SelectField('Unidad:', choices=[('Huevo', 'Huevo'),('Huevos', 'Huevos')], validators=[
        DataRequired(),
        solo_letras])


    # Campo de Polvo de Hornear
    cmbPolvo = SelectField('Ingrediente 6', choices=[('Polvo de Hornear', 'Polvo de Hornear')], validators=[
        DataRequired(),
        solo_letras
        ])

    cantHor = StringField('Cantidad ', validators=[
        DataRequired(), 
        caracteres_permitidos,
        Length(max=255)
        ])


    cmbPolvoUnidad = SelectField('Unidades:', choices=[('Gramos', 'Gramos'), ('Kilos', 'Kilos')], validators=[
        DataRequired(),
        solo_letras, 
        Length(max=255)
        ])




    # Campo de Sal
    cmbSal = SelectField('Ingrediente 7', choices=[('Sal', 'Sal')], validators=[
        DataRequired(),
        solo_letras
        ])
    cantSal = StringField('Cantidad', validators=[
        DataRequired(),
        caracteres_permitidos
        ])


    cmbSalUnidad = SelectField('Unidades:', choices=[('Gramos', 'Gramos'), ('Kilos', 'Kilos')], validators=[
        DataRequired(),
        solo_letras, 
        Length(max=255)
        ])


    # Campo de Leche
    cmbLe = SelectField('Ingrediente 8', choices=[('Leche', 'Leche')], validators=[
        DataRequired(),
        solo_letras
        ])

    cantLech = StringField('Cantidad', validators=[
        DataRequired(),
        caracteres_permitidos
        ]) 

    cmbLecheUnidad = SelectField('Unidades:', choices=[('Mililitros', 'Mililitros'), ('Litros', 'Litros')], validators=[
        DataRequired(),
        solo_letras, 
        Length(max=255)
        ])


    # Campo para el ingrediente Adicional
    adicional = StringField('Ingredientes', validators=[
        solo_letras, 
        Length(max=255)
        ])

    cantAdicional = StringField('Cantidad', validators=[
        Length(max=150)
        ])

    unidad = SelectField('Unidades:', choices=[('Gramos', 'Gramos'), ('Mililitros', 'Mililitros'), ('Litros', 'Litros'), ('Kilos', 'Kilos')], validators=[
        DataRequired(),
        solo_letras, 
        Length(max=255)
        ])

    # Campo para el procedimiento
    procedimiento = TextAreaField('Procedimiento', validators=[
        DataRequired(),
        caracteres_permitidos
        ])

    # SelectFields para el Estatus
    estatus = SelectField('Estatus', choices=[('Activo', 'Activo'), ('Inactivo', 'Inactivo')], validators=[DataRequired()])

    # Campo para el codigo de usuario
    codigoUsuario = StringField('Código de Usuario', validators=[DataRequired(), Length(max=255)])

    #imagen = FileField('Imagen')
