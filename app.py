from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, DataRequired
import email_validator
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import smtplib, ssl
from datetime import datetime
import time
from flask_socketio import SocketIO
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
import sqlite3
from sqlite3 import Error

FILE = "database.db"
LIMIT = 20
app = Flask(__name__)
clients = {}
app.config['SECRET_KEY'] = 'youwontguessthiskey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
Bootstrap(app)
db = SQLAlchemy(app)
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    email_confirmed = db.Column(db.Boolean(), nullable=False, default=False)
    online = db.Column(db.Boolean(), nullable=False, default=False)

class Messages(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client = db.Column(db.String(15), unique=False)
    message = db.Column(db.String(80))
    time = db.Column(db.String(50))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    # email_confirmed = BooleanField('email_confirmed', validators=[DataRequired(), ])


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()


        if user:
            if user.email_confirmed:
                if check_password_hash(user.password, form.password.data):
                    login_user(user, remember=form.remember.data)
                    user.online = True
                    db.session.commit()
                    session['name'] = user.username
                    return redirect(url_for('dashboard'))
                flash("Wrong password!", "info")
            else:
                flash("The account is not confirmed!", "info")
        else:
            flash("Username doesn't exist!", "info")


    return render_template('login.html', form=form)


# @app.route('/chat',methods=['GET','POST'])
# def chat():
#     return render_template('chat.html')

@app.route('/signup',methods=['GET','POST'])
def signup():
    form = RegisterForm()


    if form.validate_on_submit():
        try:
            hashed_password = generate_password_hash(form.password.data, method='sha256')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, email_confirmed=0, online=0)
            send_email(new_user)
            db.session.add(new_user)
            db.session.commit()
            flash("Please click the link we sent to your email to activate the account!")
            return redirect(url_for('login'))
        except Exception as e:
            print(e)
    return render_template('signup.html', form=form)

@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html', **{"session": session}, name= session['name'], users = get_users())


@app.route("/get_messages")
def get_messages():

    conn = sqlite3.connect(FILE)
    cursor = conn.cursor()
    query = "SELECT * FROM Messages"
    cursor.execute(query)
    result = cursor.fetchall()
    results = []
    for r in sorted(result, key=lambda x: x[3], reverse=True)[:LIMIT]:
        id, name, content, date = r
        if (name == "host"):
            continue
        data = {"name":name, "message":content, "time":str(date)}
        results.append(data)
    


    msgs = remove_seconds_from_messages(results)
    msgs = list(reversed(msgs))

    return jsonify(msgs)


@app.route("/get_name")
def get_name():
    """
    :return: a json object storing name of logged in user
    """
    data = {"name": ""}
    if 'name' in session:
        data = {"name": session['name']}
    return jsonify(data)


def get_users():
    users = User.query.all()
    return users

@app.route("/logout")
@login_required
def logout():
    """
    logs the user out by popping name from session
    :return: None
    """
    data = {"name":"host", "message":f"{session['name']} has left the channel", "time":f"{datetime.now()}"}
    s = json.dumps(data, indent=2)
    print(s)
    socketio.emit('message response', s)
    user=User.query.filter_by(username=session['name']).first()
    user.online = False
    db.session.commit()
    logout_user()
    session.pop('name', None) 
    flash("You were logged out.")
    return redirect(url_for("index"))


def send_email(user):

    port = 465  # For SSL
    smtp_server = "smtp.gmail.com"
    sender_email = "yimindiscord@gmail.com"  # Enter your address
    receiver_email = user.email  # Enter receiver address
    password = "GAOyimin615"

    msg = MIMEMultipart('alternative')

    msg['Subject'] = "Account acctivation(No-reply)"  
    msg['From'] = sender_email
    msg['To'] = receiver_email

    text = "Welcome to yimindiscord, please click the link here to acctivate your account:"
    html = f"""\
    <html>
      <head>YiminDiscord</head>
      <body>
        <p>Welcome to yimindiscord! Please click the link here to activate your account: <p>
        <a href="http://yimindiscord.com:5000/{user.username}">Activate</a></p>
      </body>
    </html>
    """
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    msg.attach(part1)
    msg.attach(part2)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())



@app.route('/<name>')
def confirm_email(name):
    user=User.query.filter_by(username=name).first()
    if user:
        user.email_confirmed = True
        db.session.commit()

        return render_template('mail.html', message="Your account has been activated!")
    else: 

        return render_template('mail.html', message="No such account!")




# COMMUNICATION FUNCTIONS


@socketio.on('event')
def handle_my_custom_event(json, methods=['GET', 'POST']):
    """
    handles saving messages once received from web server
    and sending message to other clients
    :param json: json
    :param methods: POST GET
    :return: None
    """
    data = dict(json)
    print(data)
    if "name" in data:
        new_message = Messages(client=data["name"], message=data["message"],time=datetime.now())
        db.session.add(new_message)
        db.session.commit()
    
    socketio.emit('message response', json)

# UTILITIES
def remove_seconds_from_messages(msgs):
    """
    removes the seconds from all messages
    :param msgs: list
    :return: list
    """
    messages = []
    for msg in msgs:
        message = msg
        message["time"] = remove_seconds(message["time"])
        messages.append(message)

    return messages


def remove_seconds(msg):
    """
    :return: string with seconds trimmed off
    """
    return msg.split(".")[0][:-3]


if __name__ == '__main__':
    # db.create_all()
    # app.run(debug=True)
    # app.run(host='0.0.0.0')
    socketio.run(app, debug=True, host='0.0.0.0')
