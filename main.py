from flask import Flask, render_template, redirect, flash, url_for, session, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail
from email.message import EmailMessage
import bcrypt
import random
import smtplib
import ssl
import requests
from datetime import timedelta
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET'
app.secret_key = 'SECRET'
mail = Mail(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///login.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nft.db'
Bootstrap(app)
db = SQLAlchemy(app)
app.config['GOOGLE_CLIENT_ID'] = "955190232551-us8ss1iblgsj0fb9j2u56u4glil3s3pl.apps.googleusercontent.com"
app.config['GOOGLE_CLIENT_SECRET'] = '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'
app.app_context().push()
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)
oauth = OAuth(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

google = oauth.register(
    name='google',
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
)

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Length(min=4, max=30)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min = 1, max = 80)])

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=1, max=80)])
    confirm = PasswordField('Confirm', validators=[InputRequired(), Length(min=1, max=80)])

class LoginDB(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(30), nullable = True, unique = True)
    password = db.Column(db.String(80), nullable = True)

class NFTDB(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mint = db.Column(db.String, unique=True, nullable=True)
    name = db.Column(db.String)
    symbol = db.Column(db.String)
    description = db.Column(db.String)
    colectionName = db.Column(db.String)
    colectionFamily = db.Column(db.String)
    icon = db.Column(db.String)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return LoginDB.query.get(int(user_id))

@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for("nftSearch"))
    if form.validate_on_submit():
        findUserFromDB = LoginDB.query.filter_by(email = form.email.data).first()
        if findUserFromDB is not None:
            if bcrypt.checkpw((form.password.data).encode('utf-8'), findUserFromDB.password):
                login_user(findUserFromDB)
                return redirect(url_for("nftSearch"))
            else:
                flash("Your password is incorrect")
        else:
            flash("Sorry, you don't have account")
    return render_template('Login.html', form = form)

@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        findUserFromDB = LoginDB.query.filter_by(email = form.email.data).first()
        if findUserFromDB is None:
            if form.password.data == form.confirm.data:
                cryptedPassword = bcrypt.hashpw(password= (form.password.data).encode('utf-8'), salt = bcrypt.gensalt())
                new_user = LoginDB(email = form.email.data, password = cryptedPassword)
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for("login"))
            else:
                flash("Your confirm password is incorrect")
        else:
            flash("This e-mail already exist")
    return render_template('Register.html', form = form)

@app.route('/login/google')
def loginFromGoogle():
    google = oauth.create_client('google')
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/google/authorize')
def google_authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo').json()
    user = LoginDB.query.filter_by(email = google.get('userinfo').json()['email']).first()
    if user is not None:
        login_user(user)
        return redirect(url_for("nftSearch"))
    else:
        new_user = LoginDB(email = google.get('userinfo').json()['email'], password = bcrypt.hashpw(password= (google.get('userinfo').json()['id']).encode('utf-8'), salt = bcrypt.gensalt()))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("nftSearch"))

@app.route('/forgot', methods = ['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email_sender = 'ara4matic@gmail.com'
        email_password = 'mtmyhzxvfnwqvrgg'
        codeList = []
        for i in range(8):
            codeList.append(random.choice([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]))
        code = ''
        for i in codeList:
            code += str(i)
        em = EmailMessage()
        em['From'] = email_sender
        email1 = request.form['email']
        if LoginDB.query.filter_by(email=email1).first():
            email = LoginDB.query.filter_by(email=email1).first()
            session['email'] = email.email
            session['code'] = int(code)
            em['To'] = email.email
            em['Subject'] = 'Your verification code'
            em.set_content('Please confirm your verification code ' + code)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(email_sender, email_password)
                smtp.sendmail(email_sender, request.form['email'], em.as_string())
            return redirect(url_for("code"))
    return render_template('Forgot.html')

@app.route('/code', methods = ['GET', 'POST'])
def code():
    if request.method == 'POST':
        if int(session['code']) == int(request.form['code']):
            session.pop('code')
            return redirect(url_for("newPassword"))
        else:
            flash("Incorrect code")
    return render_template('Code.html')

@app.route('/newPassword', methods = ['GET', 'POST'])
def newPassword():
    if request.method == 'POST':
        if request.form['password'] == request.form['confirm']:
            update_user = LoginDB.query.filter_by(email = session['email']).first()
            update_user.password = bcrypt.hashpw(password= (request.form['password']).encode('utf-8'), salt = bcrypt.gensalt())
            session.pop('email')
            db.session.commit()
            return redirect(url_for("home"))
        else:
            flash("Your confirm password is incorrect")
    return render_template('NewPassword.html')

@login_required
@app.route('/NFTSearch')
def nftSearch():
    if current_user.is_authenticated:
        return render_template('NFTSearch.html')
    else:
        return redirect(url_for("home"))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route('/info', methods = ['GET', 'POST'])
def info():
    if request.method == 'POST':
        address = request.form['address']
        if NFTDB.query.filter_by(mint = address).first():
            findnft = NFTDB.query.filter_by(mint = address).first()
            return render_template('Info.html', officialName=findnft.name, icon=findnft.icon, mint=findnft.mint,
                                   name=findnft.name,
                                   symbol=findnft.symbol, description=findnft.description,
                                   colectionName=findnft.colectionName, colectionFamily=findnft.colectionFamily)
        else:
            urlSolana = f'https://solana-gateway.moralis.io/nft/mainnet/{address}/metadata'
            headers = {
                "accept": "application/json",
                "X-API-Key": "10jftiyaAgczYG5YPUbRLEfaUI6uZIXFsquIdlPvkslIcExce1hIXxGyjczsGafC"
            }
            r = requests.get(urlSolana, headers=headers)
            if r.status_code == 200:
                name = r.json()['name']
                metaplexUrl = r.json()['metaplex']['metadataUri']
                icon = requests.get(metaplexUrl).json()['image']
                mint = r.json()['mint']
                symbol = requests.get(metaplexUrl).json()['symbol']
                description = requests.get(metaplexUrl).json()['description']
                colectionName = 'None'
                colectionFamily = 'None'
                collection = []
                for i in requests.get(metaplexUrl).json(): collection.append(i)
                findColection = False
                for i in collection:
                    if i == 'collection':
                        findColection = True
                    else:
                        findColection = False
                if findColection:
                    colectionName = requests.get(metaplexUrl).json()['collection']['name']
                    colectionFamily = requests.get(metaplexUrl).json()['collection']['family']
                addAddressToDb = 0
                if findColection:
                    addAddressToDb = NFTDB(mint=mint, name=name, symbol=symbol, description=description,
                                              colectionName=colectionName, colectionFamily=colectionFamily, icon=icon)
                else:
                    addAddressToDb = NFTDB(mint=mint, name=name, symbol=symbol, description=description,
                                              colectionName=colectionName, colectionFamily=colectionFamily, icon=icon)
                db.session.add(addAddressToDb)
                db.session.commit()
                return render_template('Info.html', officialName=addAddressToDb.name, icon=addAddressToDb.icon, mint=addAddressToDb.mint,
                                   name=addAddressToDb.name,
                                   symbol=addAddressToDb.symbol, description=addAddressToDb.description,
                                   colectionName=addAddressToDb.colectionName, colectionFamily=addAddressToDb.colectionFamily)
            else:
                return render_template('Error.html')



@app.route('/')
def home():
    return render_template('Home.html')

if __name__ == '__main__':
    app.run(debug = True)