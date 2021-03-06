from wtforms import Form, StringField, TextAreaField, PasswordField, BooleanField, SelectField, SubmitField, validators
from wtforms.fields.html5 import EmailField

class Formulario_Login(Form):
    usuario = StringField('Usuario', 
    [        
        validators.DataRequired(message='Dato requerido.'),
        validators.Length(min=3,max=25, message='La longitud debe estar entre 3 y 25 caracteres.')
    ])
    password = PasswordField('Contraseña', 
    [        
        validators.DataRequired(message='Dato requerido.'),
        validators.Length(min=3,max=25, message='La longitud debe estar entre 8 y 25 caracteres.')
    ])
    recordar = BooleanField('Recordar')
    enviar = SubmitField('Iniciar sesión')

class Formulario_Contacto(Form):
    nombre = StringField( 'Nombre')
    email = EmailField( 'Correo')
    mensaje = StringField( 'Mensaje' )
    operador=SelectField("Operador",choices=[("+","Sumar"),("-","Resta"),
							("*","Multiplicar"),("/","Dividir")])
    enviar = SubmitField( 'Enviar' )

class Formulario_Enviar_Mensaje(Form):
    para = StringField( 'Para', 
    [        
        validators.DataRequired(message='Dato requerido.')
    ])
    asunto = StringField( 'Asunto', 
    [        
        validators.DataRequired(message='Dato requerido.')
    ])
    mensaje = TextAreaField( 'Mensaje' , 
    [        
        validators.DataRequired(message='Dato requerido.')
    ])   
    enviar = SubmitField( 'Enviar' )

