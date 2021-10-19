import os

from flask import Flask
from flask import render_template
from flask import request
from flask import flash
from flask import redirect, url_for
from flask import jsonify
from flask import session
from flask import g
from flask import send_file
from flask import make_response
import functools
from werkzeug.security import generate_password_hash, check_password_hash

from utils import isUsernameValid, isEmailValid, isPasswordValid
import yagmail as yagmail
from forms import Formulario_Login, Formulario_Contacto, Formulario_Enviar_Mensaje
from db import get_db, close_db

app = Flask(__name__)
app.secret_key = os.urandom(24)

from mensaje import mensajes

@app.route('/')
def index():
    return redirect( url_for('send') )

# Usuario requerido:
# Es como si se estuviese llamando directamente a la función interna
def login_required(view):
    @functools.wraps( view ) # toma una función utilizada en un decorador y añadir la funcionalidad de copiar el nombre de la función.
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect( url_for( 'login' ) )
        return view( **kwargs )
    return wrapped_view
    
@app.route('/send', methods=['GET', 'POST'])
@login_required
def send():    
    form = Formulario_Enviar_Mensaje( request.form )
    if request.method == 'POST':
        # POST:
        from_id = g.user[0]
        to_usuario = form.para.data # to_id = 4
        asunto = form.asunto.data
        mensaje = form.mensaje.data

        error = None
        db = get_db()
        nom_cookie = request.cookies.get( 'username' , 'Usuario'  ) # nombre de la cookie, valor a devolver si no está la cookie.

        if not to_usuario:
            error = 'Usuario requerido.'
            flash( error )
        if not asunto:
            error = 'Asunto requerido.'
            flash( error )
        if not mensaje:
            error = 'Mensaje requerido.'
            flash( error )
        usuario_destino = db.execute(
            'SELECT id, nombre, usuario, correo, contrasena FROM Usuarios WHERE usuario = ?'
            ,
            (to_usuario,)
        ).fetchone()
        if usuario_destino is None:
            error = '{}, no existe el usuario.'.format(nom_cookie)
            flash( error )
        
        if error is not None:
            return render_template('send.html', form=form)
        else:
            db.execute(
                'INSERT INTO Mensajes (from_id,to_id,asunto,mensaje) VALUES (?,?,?,?)'
                ,
                (from_id,usuario_destino[0],asunto,mensaje)
            )
            db.commit()
            close_db()
            flash( '{}, mensaje enviado.'.format(nom_cookie) )
            form = Formulario_Enviar_Mensaje( )            
    # GET:
    return render_template('send.html', form=form)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if g.user:
        return redirect( url_for('send') )
    titulo = 'Registro'    
    if request.method == 'POST':   
        nombre = request.form['nombre']
        usuario = request.form['usuario']
        sexo = request.form['sexo']
        email = request.form['email']
        password = request.form['password']

        error = None
        db = get_db()

        if not usuario:
            error = "Usuario requerido."
            flash(error)
        if not password:
            error = "Contraseña requerida."
            flash(error)
        # 1 Validar aquí en el servidor.
        #if not isUsernameValid(usuario):
            # Está mal
        #    error = "El usuario debe ser alfanumerico o incluir solo '.','_','-'"
        #    flash(error)
        #if not isEmailValid(email):
            # Está mal
        #    error = "Correo invalido"
        #    flash(error)
        #if not isPasswordValid(password):
            # Está mal
        #    error = "La contraseña debe contener al menos una minúscula, una mayúscula, un número y 8 caracteres"
        #    flash(error)
        user_correo = db.execute(
            'SELECT * FROM Usuarios WHERE correo = ?'
            ,
            (email,)
        ).fetchone()
        if user_correo is not None:
            error = "Correo electrónico ya existe."
            flash(error)

        if error is not None:
            return render_template("registro.html", titulo=titulo)
        else:
            password_cifrado = generate_password_hash(password)
            # Segura:
            db.execute(
                'INSERT INTO Usuarios (nombre,usuario,correo,contrasena) VALUES (?,?,?,?) '
                ,
                (nombre,usuario,email,password_cifrado)
            )
            # No segura:
            #db.executescript(
            #    "INSERT INTO Usuarios (nombre, usuario, correo, contrasena) VALUES ('%s','%s','%s','%s')" % (nombre, usuario, email, password)
            #    #"; UPDATE usuario set correo='hack';"
            #) 
            db.commit()             
            # 2 Enviar un correo.
            # Para crear correo:                                    
            # Modificar la siguiente linea con tu informacion personal
            #pehernaldo2@gmail.com  Hernaldo12345678*
            #yag = yagmail.SMTP('pehernaldo2@gmail.com', 'Hernaldo12345678*') 
            #yag.send(to=email, subject='Activa tu cuenta',
            #    contents='Bienvenido, usa este link para activar tu cuenta ')
            flash('Revisa tu correo para activar tu cuenta')
            # 3 Abrir el formulario Login.
            return redirect( url_for( 'login' ) )                        
        #Tarea crear un correo de GMail para probar lo del envío de correo.
        return "Entró a registro por POST. " + usuario + email + password                
    return render_template("registro.html", titulo='Registro')
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Formulario_Login( request.form )
    if request.method == 'POST': # and form.validate():
        #VALIDACIÓN AQUÍ:
        #Usuario: Prueba
        #Contraseña: Prueba123
        usuario = form.usuario.data
        password = form.password.data

        error = None
        db = get_db()

        if not usuario:
            error = "Usuario requerido."
            flash(error)
        if not password:
            error = "Contraseña requerida."
            flash(error)
        
        if error is not None:
            # Si hay error:
            return render_template("login.html", form=form, titulo='Inicio de sesión')
        else:
            # No hay error:  
            user = db.execute(
                'SELECT id, nombre, usuario, correo, contrasena FROM Usuarios WHERE usuario = ?'
                ,
                (usuario,)
            ).fetchone()             
            print(user)            
            if user is None:
                error = "Usuario no existe."
                flash(error)
            else:
                usuario_valido = check_password_hash(user[4],password)                
                if not usuario_valido:
                    flash('Usuario y/o contraseña no son válidos.')
                    return render_template("login.html", form=form, titulo='Inicio de sesión')
                else:
                    session.clear()  
                    session['id_usuario'] = user[0]    

                    #Modifica la función login para que cuando confirme la sesión, cree una cookie
                    #del tipo ‘username’ y almacene el usuario.
                    response = make_response(  redirect( url_for('send') )  )
                    response.set_cookie( 'username' , usuario  )  # el nombre de la cookie, el valor
                    return response
    #Entró por GET
    return render_template("login.html", form=form, titulo='Inicio de sesión')

@app.before_request
def cargar_usuario_registrado():
    print("Entró en la before_request.")
    id_usuario = session.get('id_usuario')
    if id_usuario is None:
        g.user = None
    else:        
        g.user = get_db().execute(
            'SELECT id, nombre, usuario, correo, contrasena FROM Usuarios WHERE id = ?'
            ,
            (id_usuario,)
        ).fetchone()
    print('g.user:', g.user)


@app.route('/gracias', methods=['GET', 'POST'])
def graciass():
    return render_template("gracias.html", titulo='Gracias')

@app.route('/contacto', methods=['GET', 'POST'])
def contacto():    
    form = Formulario_Contacto(  request.form  )    
    if request.method == 'POST':
        flash(form.nombre.data)
        flash(form.email.data)
        flash(form.mensaje.data)        
    return render_template("contacto.html", form=form)

@app.route('/mensaje')
def message():
    return jsonify( { "mensajes": mensajes } )

@app.route('/logout')
def logout():
    session.clear()
    return redirect( url_for('login') )

@app.route('/downloadpdf')
def downloadpdf():
    return send_file( "resources/doc.pdf", as_attachment=True )

@app.route('/downloadimage')
def downloadimage():
    return send_file( "resources/image.png", as_attachment=True )


if __name__ == '__main__':
    app.run( host='127.0.0.1', port=443, ssl_context=('micertificado.pem', 'llaveprivada.pem') )

