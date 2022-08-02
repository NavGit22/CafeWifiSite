from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import AddCafe, RegisterForm, LoginForm
from flask_gravatar import Gravatar
from functools import wraps
from flask import abort


app = Flask(__name__)
app.config['SECRET_KEY'] = 'os.environ.get("SECRET_KEY")'
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url="None")


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


# CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)


# Cafe TABLE Configuration
class Cafes(db.Model):
    __tablename__ = "cafe"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    map_url = db.Column(db.String(500), nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    location = db.Column(db.String(250), nullable=False)
    seats = db.Column(db.String(250), nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    can_take_calls = db.Column(db.Boolean, nullable=False)
    coffee_price = db.Column(db.String(250), nullable=True)


@app.route('/')
def get_all_cafes():
    cafes = Cafes.query.all()
    return render_template("index.html", all_cafes=cafes, current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(email=form.email.data).first()
        if user:
            flash('You have already signed up with that email, log in instead', 'error')
            return render_template('login.html')
        else:
            hash_password = generate_password_hash(
                password=form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=form.email.data,
                password= hash_password,
                name=form.name.data
            )
            db.session.add(new_user)
            db.session.commit()

            # Log in and authenticate user after adding details to database.
            login_user(new_user)

            cafes = Cafes.query.all()
            return render_template('index.html', all_cafes=cafes, current_user=current_user)

    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = db.session.query(User).filter_by(email=email).first()
        if not user:
            flash('That email does not exist, please try again', 'error')
        else:
            if not check_password_hash(user.password, password):
                flash('Password incorrect, please try again', 'error')
            else:
                login_user(user)
                cafes = Cafes.query.all()

                return render_template('index.html', all_cafes=cafes, current_user=current_user)
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_cafes'))


@app.route("/cafe/<int:cafe_id>", methods=['GET', 'POST'])
def show_cafe(cafe_id):
    requested_cafe = Cafes.query.get(cafe_id)
    return render_template("cafe.html", cafe=requested_cafe, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route("/new-cafe", methods=['GET', 'POST'])
# @admin_only
def add_new_cafe():
    form = AddCafe()
    if form.validate_on_submit():
        new_cafe = Cafes(
            name=form.name.data,
            map_url=form.map_url.data,
            img_url=form.img_url.data,
            location=form.location.data,
            seats=form.seat.data,
            has_toilet=form.has_toilet.data,
            has_wifi=form.has_wifi.data,
            has_sockets=form.has_sockets.data,
            can_take_calls=form.can_take_calls.data,
            coffee_price=form.coffee_price.data
        )
        db.session.add(new_cafe)
        db.session.commit()
        return redirect(url_for("get_all_cafes"))
    return render_template("add-cafe.html", form=form, current_user=current_user)


@app.route("/delete/<int:cafe_id>", methods=['GET', 'DELETE'])
@admin_only
def delete_cafe(cafe_id):
    cafe_to_delete = Cafes.query.get(cafe_id)
    db.session.delete(cafe_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_cafes'))


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, host='localhost', port=5000)
