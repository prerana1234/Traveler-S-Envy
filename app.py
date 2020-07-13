import os
import base64
from io import BytesIO
from flask import Flask, request, render_template, redirect, url_for, flash, session, \
    abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
    current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo


app = Flask(__name__)
app.config.from_object('config')

db = SQLAlchemy(app)
lm = LoginManager(app)

class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    email = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    """Registration form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    email = StringField('Email', validators=[Required()])
    password = PasswordField('Password', validators=[Required()])
    password_again = PasswordField('Password again',
                                   validators=[Required(), EqualTo('password')])
    contact = StringField('Contact', validators=[Required()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """Login form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    #token = StringField('Token', validators=[Required(), Length(6, 6)])
    submit = SubmitField('Login')

@app.route('/register' )
def register():
    """User registration route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('hello1'))
    return render_template('signup.html')



@app.route('/register', methods=[ 'POST'])
def register_post():
    form = RegisterForm();
    """User registration route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('hello1'))
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user is not None:
        flash('Username already exists.')
        return redirect(url_for('register'))
    # add new user to the database
    user = User(username=username, email=email, password=password)
    db.session.add(user)
    db.session.commit()
    # redirect to the two-factor auth page, passing username in session
    session['username'] = user.username
    return redirect(url_for('hello1'))
    return render_template('signup.html', form=form)



@app.route('/')
def hello1():
	return redirect(url_for('hello'))

@app.route('/index')
def hello():
	return render_template('index.html')


@app.route('/trip-1')
def trip1():
	return render_template('trip-1.html')

@app.route('/trip-2')
def trip2():
	return render_template('trip-2.html')	

@app.route('/trip-3')
def trip3():
	return render_template('trip-3.html')	

@app.route('/flight-1')
def flight1():
     return render_template('flight-1.html')

@app.route('/flight-details')
def flightdetails():
     return render_template('flight-details.html')	     	

@app.route('/hotel-1')
def hotel1():
     return render_template('hotel-1.html')

@app.route('/hotel-2')
def hotel2():
     return render_template('hotel-2.html')  

@app.route('/hotel-3')
def hotel3():
     return render_template('hotel-3.html')        

@app.route('/train-1')
def train():
     return render_template('train-1.html') 

@app.route('/train-2')
def train2():
     return render_template('train-2.html')     

@app.route('/car-1')
def car1():
     return render_template('car-1.html')

@app.route('/car-2')
def car2():
     return render_template('car-2.html')       

@app.route('/help')
def help():
     return render_template('help.html') 

@app.route('/service-1')
def service():
     return render_template('service-1.html') 

@app.route('/contact')
def contact():
     return render_template('contact.html') 

@app.route('/home-work')
def homework():
     return render_template('home-work.html')  


@app.route('/afflite')
def afflite():
     return render_template('afflite.html') 

@app.route('/about')
def about():
     return render_template('about.html')      

@app.route('/index', methods= ['POST'])
def hello2():
    if current_user.is_authenticated:
        # if user is logged in we get out of here  or not user.verify_totp(form.token.data)
        return redirect(url_for('hello1'))
    form = LoginForm()
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user is None or not user.verify_password(password) :
        flash('Invalid username, password or token.')
        return redirect(url_for('hello1'))
    # log user in
    login_user(user)
    #flash('You are now logged in!')
    return render_template('index.html', form=form)
db.create_all()

if __name__ == '__main__':
	app.run()
