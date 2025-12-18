import os
import datetime
import smtplib

from email.mime.text import MIMEText

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from peewee import SqliteDatabase, Model, CharField, ForeignKeyField, SmallIntegerField, BooleanField, DateTimeField, fn

from wtforms import Form, StringField, FileField, SelectMultipleField
from wtforms.validators import InputRequired, Email, ValidationError

from flask import Flask, redirect, url_for, request, render_template, send_from_directory, current_app, flash
from markupsafe import Markup
from flask_admin import Admin, helpers
from flask_admin.form import Select2Widget
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_admin.contrib.peewee import ModelView
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Message, Mail

from apscheduler.schedulers.background import BackgroundScheduler


ZERO_DATE = datetime.datetime(1, 1, 1, 0, 0, 0)
DB_PATH = "DB_biblioteca.db"

app = Flask(__name__)
app.config.update(UPLOAD_FOLDER=os.path.join(app.root_path, 'static/bookcovers'),
                  ALLOWED_EXTENSIONS=set(['jpg','jpeg','webp','png']),
                  SECRET_KEY='123456789')

app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
#app.config['MAIL_USERNAME'] = 'apikey'
#app.config['MAIL_PASSWORD'] = 'your_sendgrid_api_key' TESTEAR------------------------------------
app.config['MAIL_DEFAULT_SENDER'] = ('My Library App', 'noreply@mylibrary.com')
app.config['SECURITY_PASSWORD_SALT'] = 'saldetesteoviste'
admin = Admin(app, name="bibliotecaCRUD", template_mode='bootstrap3')
mail = Mail(app)

def allowed_file(filename):
    file_ext = filename.rsplit('.',1)[1] if filename else ''
    if file_ext in app.config['ALLOWED_EXTENSIONS']:
        return (True, file_ext)
    return (False, file_ext)

def init_login(app):
    login_manager = LoginManager()
    login_manager.init_app(app)

    @login_manager.unauthorized_handler
    def unauth_handler():
        return redirect(url_for('login'))

    @login_manager.user_loader
    def load_user(user_id):
        return User.get_or_none(User.id == user_id)

def generate_token(user_email):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return s.dumps(user_email, salt=current_app.config['SECURITY_PASSWORD_SALT'])

def verify_token(token, max_age=1800):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=max_age)
    except Exception:
        return None
    return email

def send_email(to_email, subject, body):
    from_email = "flasknahtesteo@gmail.com"
    password = "mubm lazt qvut xyab"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(from_email, password)
        server.send_message(msg)

database = SqliteDatabase('DB_biblioteca.db')

class BaseModel(Model):
    class Meta:
        database = database

class UserRole(BaseModel):
    role = CharField(unique=True, max_length=32)

class User(BaseModel, UserMixin):
    username = CharField(unique=True, max_length=100)
    password = CharField()
    email = CharField(unique=True, max_length=254)
    role = ForeignKeyField(UserRole, backref='userrole')

class UnverifiedUser(BaseModel):
    user = ForeignKeyField(User, backref='verification', primary_key=True, on_delete='CASCADE')
    email = CharField(unique=True, max_length=254)
    created_at = DateTimeField(default=datetime.datetime.now)

class Author(BaseModel):
    author = CharField(unique=True, max_length=150)

class Editorial(BaseModel):
    editorial = CharField(unique=True, max_length=150)

    def __str__(self):
        return self.editorial

class Genre(BaseModel):
    genre = CharField(unique=True, max_length=50)

class Book(BaseModel):
    title = CharField(unique=True, max_length=255)
    year = SmallIntegerField()
    editorial = ForeignKeyField(Editorial, backref='editorials')
    bookcover = CharField(unique=True)
    ismissing = BooleanField(null=True)

    def genre_list(self):
        query = (Genre
                 .select(Genre.genre)
                 .join(BookGenre)
                 .where(BookGenre.book == self))
        return ", ".join([g.genre for g in query])

    def author_list(self):
        query = (Author
                 .select(Author.author)
                 .join(BookAuthor)
                 .where(BookAuthor.book == self))
        return ", ".join([a.author for a in query])

    def get_state(self):
        if self.ismissing:
            return {
                "available" : False,
                "state": "No Disponible",
                "top_color": "#999",
                "bottom_color": "#555"
            }

        rent = (Rent
                .select()
                .where(Rent.book_id == self)
                .first())

        if not rent:
            return {
                "available" : True,
                "state": "Disponible",
                "top_color": "#06EA00",
                "bottom_color": "#006431"
            }

        if not rent.has_book:
            return {
                "available" : False,
                "state": "Reservado",
                "top_color": "#b38600",
                "bottom_color": "#644b00"
            }

        if rent.return_date < datetime.datetime.now():
            return {
                "available" : False,
                "state": "Atrasado",
                "top_color": "#000000",
                "bottom_color": "#535353"
            }

        return {
            "available" : False,
            "state": "En Uso",
            "top_color": "#D90057",
            "bottom_color": "#8B0000"
        }

class BookGenre(BaseModel):
    book = ForeignKeyField(Book, backref='book_genres')
    genre = ForeignKeyField(Genre, backref='genres')

class BookAuthor(BaseModel):
    book = ForeignKeyField(Book, backref='book_authors')
    author = ForeignKeyField(Author, backref='authors')

class Rent(BaseModel):
    book_id = ForeignKeyField(Book, backref='books_id', primary_key=True)
    user_id = ForeignKeyField(User, backref='users_id')
    has_book = BooleanField(null=True, default=False)
    weeks = SmallIntegerField(null=False)
    start_date = DateTimeField(default=ZERO_DATE)
    return_date = DateTimeField(default=ZERO_DATE)

class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role_id == 2

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'))

class RentView(AdminModelView):
    column_list = ('book_title', 'user_username', 'has_book', 'start_date', 'return_date')

    column_formatters = {
        'book_title': lambda v, c, m, p: m.book_id.title if m.book_id else 'Invalido',
        'user_username': lambda v, c, m, p: m.user_id.username if m.user_id else 'Invalido'
    }


    def on_model_change(self, form, model, is_created):
        if model.has_book and model.start_date == ZERO_DATE:
            model.start_date = datetime.datetime.now()
            model.return_date = model.start_date + datetime.timedelta(days = (model.weeks * 7))

        return super().on_model_change(form, model, is_created)

    column_labels = {
        'book_title': 'Libro',
        'user_username': 'Usuario',
        'has_book': 'Usuario Posee Libro',
        'start_date': 'Fecha de comienzo',
        'return_date': 'Fecha de retorno',
        'before_due_notif': ''
    }
    #column_searchable_list = ('book_title', 'user_username')

class BookView(AdminModelView):
    column_list = ('book_cover', 'title', 'genre_list', 'year', 'author_list', 'editorial', 'ismissing')

    column_formatters = {
        'book_cover': lambda v, c, m, p: Markup(
            f'<img src="{url_for("static", filename="bookcovers/" + m.bookcover)}" '
            f'style="max-height:100px;"'
            f'onerror="this.onerror=null; this.src=\'{url_for("static", filename="img/default.png")}\';">'
        ),
        'genre_list': lambda v, c, m, p: m.genre_list(),
        'author_list': lambda v, c, m, p: m.author_list()
    }

    column_labels = {
        'book_cover': 'Portada',
        'title': 'Titulo',
        'genre_list': 'Genero/s',
        'year': 'Año',
        'author_list': 'Autor/es',
        'editorial': 'Editorial',
        'ismissing': 'No esta disponible?'
    }

    column_sortable_list = {
        'title': Book.title,
        'year': Book.year,
        'editorial': (Editorial, 'editorial'),  # 👈 sort by the name, not the ID
    }

    form_extra_fields = {
        'book_cover': FileField('Subir Portada'),
        'genres': SelectMultipleField(
            'Genres',
            coerce=int,
            widget=Select2Widget(multiple=True)
        ),
        'authors': SelectMultipleField(
            'Authors',
            coerce=int,
            widget=Select2Widget(multiple=True)
        )
    }

    form_create_rules = form_edit_rules = ['book_cover', 'title', 'genres', 'year', 'authors', 'editorial', 'ismissing']

    form_excluded_columns = ('bookcover',)

    def on_form_prefill(self, form, id):
        book = Book.get_by_id(id)
        form.genres.data = [bg.genre.id for bg in book.book_genres]
        form.authors.data = [ba.author.id for ba in book.book_authors]


    def create_form(self, obj=None):
        form = super().create_form(obj)
        form.genres.choices = [(g.id, g.genre) for g in Genre.select()]
        form.authors.choices = [(a.id, a.author) for a in Author.select()]
        return form


    def edit_form(self, obj=None):
        form = super().edit_form(obj)
        form.genres.choices = [(g.id, g.genre) for g in Genre.select()]
        form.authors.choices = [(a.id, a.author) for a in Author.select()]
        return form


    def on_model_change(self, form, model, is_created):
        # Save uploaded file if present or delete old image in case of image change
        upload = form.book_cover.data
        
        if is_created and not upload:
            raise ValidationError("Necesita subir una imagen como portada para crear un libro.")

        if upload:
            filename = secure_filename(upload.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)


            base, ext = os.path.splitext(filename)
            if ext.rsplit('.',1)[1] not in app.config['ALLOWED_EXTENSIONS']:
                raise ValidationError('Formato de imagen no permitido, solo se admite (jpg, jpeg, png)')
            
            counter = 1
            while os.path.exists(filepath):
                filename = f"{base}_{counter}{ext}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                counter += 1
            upload.save(filepath)


            if model.bookcover != "default.png" and not is_created:
                oldFilePath = os.path.join(app.config['UPLOAD_FOLDER'], model.bookcover)
                if os.path.exists(oldFilePath):
                    os.remove(oldFilePath)

            model.bookcover = filename
    

    def after_model_change(self, form, model, is_created):
        # Update genres
        BookGenre.delete().where(BookGenre.book == model).execute()
        for genre_id in form.genres.data:
            BookGenre.create(book=model, genre=genre_id)

        # Update authors
        BookAuthor.delete().where(BookAuthor.book == model).execute()
        for author_id in form.authors.data:
            BookAuthor.create(book=model, author=author_id)

    def on_model_delete(self, model):
        if model.bookcover and model.bookcover != "default.png":
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], model.bookcover)
            if os.path.exists(filepath):
                os.remove(filepath)

admin.add_view(AdminModelView(User))
admin.add_view(BookView(Book))
admin.add_view(RentView(Rent))
admin.add_view(AdminModelView(Author))
admin.add_view(AdminModelView(Editorial))
admin.add_view(AdminModelView(Genre))
admin.add_view(AdminModelView(UnverifiedUser))
admin.add_view(AdminModelView(UserRole))


def autoDeleteUnverifiedUsers():
    cutoff = datetime.datetime.now() - datetime.timedelta(days=1)
    expired = (
        UnverifiedUser
        .select(UnverifiedUser.user)
        .where(UnverifiedUser.created_at < cutoff)
    )
    User.delete().where(User.id.in_(expired)).execute()
    UnverifiedUser.delete().where(UnverifiedUser.created_at < cutoff).execute()

scheduler = BackgroundScheduler()
scheduler.add_job(func=autoDeleteUnverifiedUsers, trigger="interval", seconds=10)
scheduler.start()


class LoginForm(Form):
    username = StringField('Username', validators=[InputRequired()])
    password = StringField('Password', validators=[InputRequired()])

    def user_from_db(self):
        return User.get_or_none(User.username == self.username.data)

    def validate_username(self, field):
        if not self.user_from_db:
            raise ValidationError('Invalid username or password') #RECOMENDACION: NUNCA INDICAR SI UN DATO ESPECIFICO ES INVALIDO, ESTO CONFIRMA LA EXISTENCIA DE OTROS DATOS

    def validate_password(self, field):
        if not check_password_hash(self.user_from_db().password, self.password.data):
            raise ValidationError('Invalid username or password') #RECOMENDACION: NUNCA INDICAR SI UN DATO ESPECIFICO ES INVALIDO, ESTO CONFIRMA LA EXISTENCIA DE OTROS DATOS

class SignUpForm(Form):
    username = StringField('Username', validators=[InputRequired()])
    password = StringField('Password', validators=[InputRequired()])
    email = StringField('Email', validators=[InputRequired(), Email()])

    def validate_username(self, field):
        if User.get_or_none(User.username == self.username.data):
            raise ValidationError('User name is already taken')

    def validate_email(self, field):
        if User.get_or_none(User.email == self.email.data):
            raise ValidationError('Email is already taken')

class CommonForm(Form):
    text = StringField('', validators=[InputRequired()])


@app.route('/')
def index():
    form = CommonForm(request.form)
    books = Book.select().order_by(Book.id).limit(10)
    randomGenres = Genre.select().join(BookGenre, on=(BookGenre.genre == Genre.id)).distinct().order_by(fn.Random()).limit(3)
    randomBooksGenres = []
    for gen in randomGenres:
        booksGenres = Book.select().join(BookGenre, attr='BG').where(BookGenre.genre == gen.id).order_by(fn.Random()).limit(6)
        randomBooksGenres.append(booksGenres)
    rents = Rent.select()
    return render_template('index.html', books=books, rents=rents, form=form, randomGenres=randomGenres, randomBooksGenres=randomBooksGenres, mensaje="inicio")

@app.route('/login', methods=('GET','POST'))
def login():
    form = LoginForm(request.form) 
    if helpers.validate_form_on_submit(form):
        user = form.user_from_db()
        if UnverifiedUser.get_or_none(UnverifiedUser.user == user):
            flash('La cuenta a la que intenta acceder aun no se encuentra verificada.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html', form=form, mensaje="Inicio de sesion")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/signup', methods=('GET','POST'))
def signup():
    form = SignUpForm(request.form)
    if helpers.validate_form_on_submit(form):
        email = request.form['email']
        password = generate_password_hash(form.data['password'])
        token = generate_token(form.data['email'])
        with database.transaction():
            user = User.create(
                    username=form.data['username'],
                    password=password,
                    email=email
            )
            UnverifiedUser.create(user_id=user.id, email=email, created_at=datetime.datetime.now())
            link = url_for('verify_email', token=token, _external=True)
            body = f"""Hola, aca le mandamos el link para verificar cuenta

            {link}

            Saludos,
            Biblioteca Digital
            """
            send_email(email, "Verificacion de Cuenta", body)
            flash('Se ha enviado un enlace de verificacion a la dirección de correo electrónico, si el mensaje no aparece revise la categoria spam.')
            #login_user(user)
            return redirect(url_for('signup'))
    return render_template('signup.html', form=form, mensaje="registrar cuenta")

@app.route('/bookcover/<path:cover_path>')
def bookcover(cover_path):
    return send_from_directory(app.config['UPLOAD_FOLDER'], cover_path)

@app.route('/bookdetail/<path:book_id>')
def bookdetail(book_id):
    books = Book.select(Book.id, Book.title, Book.year, Editorial.editorial, Book.bookcover, Book.ismissing).join(Editorial, attr='editorial').switch(Book).where(Book.id == book_id).limit(1)
    authors = Author.select(Author.author).join(BookAuthor, attr='BA').where(BookAuthor.book == book_id)
    genres = Genre.select(Genre.genre).join(BookGenre, attr='BG').where(BookGenre.book == book_id)
    return render_template('book_detail.html', books=books, genres=genres, authors=authors, mensaje="datos de libro")

@app.route('/userdetail/<path:user_id>')
def userdetail(user_id):
    user = User.select().where(User.id == user_id)
    books = Book.select(Book.id, Book.bookcover, Rent.return_date, Rent.has_book).join(Rent, attr='rent').switch(Book).where(Rent.user_id == user_id)
    return render_template('user_detail.html', books=books, user=user, mensaje="datos de usuario")

@app.route('/search', methods=('GET','POST'))
def search():
    form = CommonForm(request.form)
    if request.method == 'POST':
        searchMethod = request.form['method']
        if helpers.validate_form_on_submit(form):
            rents = Rent.select()
            if searchMethod == "title":
                booksname = Book.select().where(Book.title.contains(form.text.data)).group_by(Book.id)
            elif searchMethod == "author":
                booksname = Book.select(Book.id, Book.bookcover, Author.author).join(BookAuthor, attr='BA').join(Author, attr='author').switch(Book).where(Author.author.contains(form.text.data)).group_by(Book.id)
            elif searchMethod == "genre":
                booksname = Book.select(Book.id, Book.bookcover, Genre.genre).join(BookGenre, attr='BA').join(Genre, attr='genre').switch(Book).where(Genre.genre.contains(form.text.data)).group_by(Book.id)
            return render_template('search.html', form=form, booksname=booksname, rents=rents, mensaje="buscar libro")
    else:
        return render_template('search.html', form=form)

@app.route('/message/<int:book_id>/<int:user_id>', methods=['POST'])
@login_required
def messagelog(book_id, user_id):
    semanas = int(request.form["semana"])
    bookHasUser = Rent.get_or_none(Rent.book_id == book_id)
    bookIsMissing = Book.get(Book.id == book_id).ismissing
    if (bookIsMissing == False) and (bookHasUser == None) and (user_id == current_user.id):
        with database.transaction():
            Rent.create(
                book_id=book_id,
                user_id=user_id,
                has_book=False,
                weeks=semanas
                #return_date=datetime.datetime.now() + datetime.timedelta(days = (7 * semanas))
            )
            return render_template('message.html', message='Prestamo realizado con exito!')
    if user_id != current_user.id:
        message='Error: Usuario actual no coincide con el pedido'
    elif bookHasUser != None:
        message=f'Error: El libro ya esta rentado {semanas}'
    else:
        message='Error: El libro no se encuentra disponible'
    return render_template('message.html', message=message, mensaje="resultado")

@app.route('/change-password/<token>', methods=['GET', 'POST'])
def change_password(token):
    email = verify_token(token)
    if not email:
        flash('El enlace de reinicio no es válido o ha caducado.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed = generate_password_hash(new_password)
        user = User.get(User.email == email)
        user.password = hashed
        user.save()

        flash('¡Su contraseña ha sido actualizada!')
        return redirect(url_for('login'))

    return render_template('change_password.html', token=token, mensaje="cambio de contraseña")

@app.route('/request_password_change', methods=['GET', 'POST'])
def requestpasswordchange():
    form = CommonForm(request.form)
    if request.method == "POST":
        email = form.text.data
        user = User.get_or_none(User.email == email)
        if user:
            reset_url = url_for('change_password', token=generate_token(email), _external=True)
            body = f"""Hola,

            {reset_url}

            Best regards,
            Your Library App
            """
            send_email(email, "Cambio de Contraseña", body)
            #send_reset_email(user, token)
        flash('Se ha enviado un enlace de reinicio a la dirección de correo electrónico proporcionada, si el mensaje no aparece revise la categoria spam.')
        return redirect(url_for('login'))

    return render_template('request_password_change.html', form=form, mensaje="cambiar contraseña")

@app.route('/verify/<token>')
def verify_email(token):
    email = verify_token(token)
    if not email:
        flash('El enlace de verificación no es válido o ha expirado.')
        return redirect(url_for('signup'))

    try:
        user = User.get(User.email == email)
    except User.DoesNotExist:
        flash('Usuario no encontrado.')
        return redirect(url_for('signup'))

    try:
        u = UnverifiedUser.get(UnverifiedUser.email == email)
    except UnverifiedUser.DoesNotExist:
        flash('No se encontró una cuenta no verificada para este correo electrónico.')
        return redirect(url_for('signup'))

    u.delete_instance()

    flash('¡Su cuenta ha sido verificada! Ya puedes iniciar sesión.')
    return redirect(url_for('login'))

init_login(app)


if __name__ == '__main__':
    #with database:
        #database.create_tables([UserRole])
    if not os.path.exists(DB_PATH):
        with database:
            database.create_tables([UserRole, User, UnverifiedUser, Author, Editorial, Genre, Book, BookGenre, BookAuthor, Rent])

    app.run(debug=True)


print("END OF LOG") #SACAR ESTO PARA CUANDO SE TERMINE EL CODIGO VISTE