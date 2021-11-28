from flask_wtf import FlaskForm
from flask_wtf.file import FileField,FileAllowed
from wtforms import StringField,PasswordField,SubmitField,BooleanField
from wtforms.validators import DataRequired, Email,Length,EqualTo,ValidationError
from flask_login import current_user
from flaskblog.models import User


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(),Length(min=2, max= 20)])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField("Sign Up")

    def validate_username(self,username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists! Please try another username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email address is already used in another account')


class LoginForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')    
    submit = SubmitField("Login")

class UpdateForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(),Length(min=2, max= 20)])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture',validators=[FileAllowed(['jpg','jpeg','png'])])
    submit = SubmitField("Update")

    def validate_username(self,username):
        if current_user.username != username.data:   
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username already exists! Please try another username.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('Email address is already used in another account')


class RequestResetForm(FlaskForm):
    email = StringField("Email Address",validators=[DataRequired(),Email()])
    submit = SubmitField("Request Password Reset")

    def validate_email(self,email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError("There is no account registered with this email. Please register first.")

class ResetPasswordForm(FlaskForm):
    password = PasswordField("New Password",validators=[DataRequired()])
    confirm_password = PasswordField("Confirm New Password",validators=[DataRequired(),EqualTo("password")])
    submit = SubmitField("Reset Password")