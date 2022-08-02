from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, IntegerField
from wtforms.validators import DataRequired, URL, Email


# WTForm
class AddCafe(FlaskForm):
    name = StringField("Cafe Name", validators=[DataRequired()])
    map_url = StringField("Map URL", validators=[DataRequired(), URL()])
    img_url = StringField("Image URL", validators=[DataRequired(), URL()])
    location = StringField("Location", validators=[DataRequired()])
    seat = StringField("Seat Capacity", validators=[DataRequired()])
    has_toilet = BooleanField("Has Toilet")
    has_wifi = BooleanField("Has Wifi")
    has_sockets = BooleanField("Has Sockets")
    can_take_calls = BooleanField("Can take calls")
    coffee_price = StringField("Coffee Price", validators=[DataRequired()])
    submit = SubmitField("Add Cafe")


# Register Form
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")


# Login Form
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")

