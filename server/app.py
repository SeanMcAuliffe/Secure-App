from flask import Flask, jsonify, request, abort
from flask_login import login_user, login_required, logout_user, UserMixin, LoginManager
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///seng360.sqlite3'

db = SQLAlchemy(app)

app.secret_key = 'super secret key'

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):
    #__tablename__ = 'users'
    id = db.Column('id', db.Integer, primary_key = True)
    username = db.Column(db.String(100))
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = password

    def verify_password(self, password):
        return password == self.password_hash

with app.app_context():
    db.create_all()

@app.route('/')
def hello_world():
    return 'This is my first API call!'

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400) # missing arguments
    if User.query.filter_by(username = username).first() is not None:
        abort(400) # existing user
    user = User(username = username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return 'register'

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400) # missing arguments
    user = User.query.filter_by(username=username).first()
    print(user)
    if not user or not user.verify_password(password):
        print(user.username)
        print(user.password_hash)
        abort(406)
    else:
        login_user(user, remember=True)
    return 'login'

@app.route('/delete')
@login_required
def delete():
    return 'delete'

@app.route('/logout')
@login_required
def logout():
    logout_user();
    return 'logout'
