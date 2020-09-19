from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flaskblog.models import User

class RegistrationForm(FlaskForm):
	username = StringField('Kullanıcı Adı', validators=[DataRequired(), Length(min=2, max=20)])
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Şifre', validators=[DataRequired()])
	confirm_password = PasswordField('Şifreyi Onayla', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Kayıt Ol') 

	def validate_username(self, username):
		user = User.query.filter_by(username=username.data).first()
		if user:
			raise ValidationError('Kullanıcı adı daha önce alınmış, başka bir tane deneyin.')

	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user:
			raise ValidationError('Email kullanımda, başka bir tane deneyin.')

class LoginForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])
	password = PasswordField('Şifre', validators=[DataRequired()])
	remember = BooleanField('Beni Hatırla')
	submit = SubmitField('Giriş')



class UpdateAccountForm(FlaskForm):
	username = StringField('Kullanıcı Adı', validators=[DataRequired(), Length(min=2, max=20)])
	email = StringField('Email', validators=[DataRequired(), Email()])
	picture = FileField('Profil Fotoğrafı', validators=[FileAllowed(['jpg','png','jpeg'])])
	submit = SubmitField('Kaydet') 

	def validate_username(self, username):
		if username.data != current_user.username:
			user = User.query.filter_by(username=username.data).first()
			if user:
				raise ValidationError('Kullanıcı adı daha önce alınmış, başka bir tane deneyin.')

	def validate_email(self, email):
		if email.data != current_user.email:
			user = User.query.filter_by(email=email.data).first()
			if user:
				raise ValidationError('Email kullanımda, başka bir tane deneyin.')


class PostForm(FlaskForm):
	dosya = FileField('Döküman Yolla', validators = [FileAllowed(["jpg","png","jpeg","docx","pptx","ppt","txt","pdf"])])
	title = StringField('Başlık', validators=[DataRequired()])
	content = TextAreaField('İçerik', validators=[DataRequired()])
	submit = SubmitField('Gönder')


class RequestResetForm(FlaskForm):
	email = StringField('Email', validators=[DataRequired(), Email()])
	submit = SubmitField('Şifre Sıfırlama İsteği')

	def validate_email(self, email):
		user = User.query.filter_by(email=email.data).first()
		if user is None:
			raise ValidationError('Böyle bir hesap yok.')

class ResetPasswordForm(FlaskForm):
	password = PasswordField('Şifre', validators=[DataRequired()])
	confirm_password = PasswordField('Şifreyi Onayla', validators=[DataRequired(), EqualTo('password')])
	submit = SubmitField('Şifreyi Sıfırla')