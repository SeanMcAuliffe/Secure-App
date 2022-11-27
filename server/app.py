from flask import Flask, json, jsonify, request, abort
from flask_login import login_user, login_required, logout_user, UserMixin, LoginManager, current_user
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///seng360.sqlite3'

db = SQLAlchemy(app)

app.secret_key = 'UFGHIk6QX2y6je12JYi0SBVnciAFL71i' ## should move this to an environmental variable

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column('id', db.Integer, primary_key = True)
    username = db.Column(db.String(100))
    password_hash = db.Column(db.String(128))
    pubkey = db.Column(db.String(2000)) ## might need to change
    isActive = db.Column(db.Boolean, default=False)
    socket_ip = db.Column(db.String(20))
    socket_port = db.Column(db.Integer)

    def hash_password(self, password):
        self.password_hash = sha256_crypt.encrypt(password)
    def verify_password(self, password):
        return sha256_crypt.verify(password, self.password_hash)

with app.app_context():
    db.create_all()

@app.route('/')
def hello_world():
    return 'This is my first API call!'


"""
Registers an account

Request Parameters:
    {
        "username": String,
        "passord": String,
        "pubkey": String,
    }

Response:
    400: missing request parameters
    401: invalid username/password
    200: successfully registered an account
"""
@app.route('/register', methods=['POST'])
def register():
    incoming_json = request.json
    json_dict = json.loads(incoming_json)
    if 'username' not in json_dict or 'password' not in json_dict or 'pubkey' not in json_dict:
        abort(400)
    username = json_dict['username']
    password = json_dict['password']
    pubkey = json_dict['pubkey']
    if username is None or password is None or pubkey is None:
        abort(400) # missing arguments
    if User.query.filter_by(username = username).first() is not None:
        abort(401) # existing user
    user = User(username = username, pubkey=pubkey)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return 'register'


"""
Logs into the service and creates a session with the server 

Request Parameters:
    {
        "username": String,
        "passord": String,
        "ip": String,
        "port" Int
    }

Response:
    400: missing request parameters
    401: invalid username/password
    200: sucessfully authenticated
"""
@app.route('/login', methods=['POST'])
def login():
    incoming_json = request.json
    json_dict = json.loads(incoming_json)
    if 'username' not in json_dict or 'password' not in json_dict or 'ip' not in json_dict or 'port' not in json_dict:
        abort(400)
    username = json_dict['username']
    password = json_dict['password']
    ip = json_dict['ip']
    port = json_dict['port']
    if username is None or password is None or ip is None or port is None:
        abort(400) # missing arguments

    user = User.query.filter_by(username=username).first()

    if not user or not user.verify_password(password):
        abort(401)
    else:
        user.isActive = True
        user.socket_port = port
        user.socket_ip = ip
        db.session.commit()
        login_user(user, remember=True)
    return 'login'

"""
Deletes an account

Response:
    200: successfully deletes the authenticated users account
"""
@app.route('/delete_account')
@login_required
def delete_account():
    User.query.filter_by(id=current_user.get_id()).delete()
    db.session.commit()
    logout_user()
    return 'delete'

"""
Logs out of the current session

Response:
    200: successfully logged out of the current session
"""
@app.route('/logout')
@login_required
def logout():
    user = User.query.filter_by(id=current_user.get_id()).first()
    user.isActive = False
    db.session.commit()
    logout_user()
    return 'logout'

"""
Retrieves the required details in order to initiate a tcp session provided the desired user is active (currently has a session with the server)

Request Parameters:
    {
        "recipient_username": String,
    }

Response:
    404: User not found
    410: User not active
    200: successfully registered an account

Sucessful Response Parameters:
    {
        "ip": String,
        "port": Int,
        "pubkey": String
    }
"""
@app.route('/create_session',methods=['POST'])
@login_required
def retrieve_new_message():
    incoming_json = request.json
    json_dict = json.loads(incoming_json)
    if 'recipient_username' not in json_dict:
        abort(400)
    recipientUsername = json_dict['recipient_username']

    recipientUser = User.query.filter_by(username=recipientUsername).first()

    if(recipientUser is None):
        abort(404)
    if(not recipientUser.isActive):
        abort(410)

    outbound = {"ip": recipientUser.socket_ip, "port": recipientUser.socket_port, "pubkey": recipientUser.pubkey}
    return jsonify(outbound)

if __name__ == "__main__":
    app.run(debug=True)
