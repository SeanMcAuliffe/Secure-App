from flask import Flask, json, jsonify, request, abort
from flask_login import login_user, login_required, logout_user, UserMixin, LoginManager, current_user
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
    __tablename__ = 'users'
    id = db.Column('id', db.Integer, primary_key = True)
    username = db.Column(db.String(100))
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = password

    def verify_password(self, password):
        return password == self.password_hash

class Messages(db.Model):
    id = db.Column('id',db.Integer,primary_key = True)
    receiver = db.Column(db.Integer, db.ForeignKey("users.id"))
    sender = db.Column(db.Integer, db.ForeignKey("users.id"))
    message = db.Column(db.String(1000))



with app.app_context():
    db.create_all()

@app.route('/')
def hello_world():
    return 'This is my first API call!'

@app.route('/register', methods=['POST'])
def register():
    incoming_json = request.json
    json_dict = json.loads(incoming_json)
    username = json_dict['username']
    password = json_dict['password']
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
    incoming_json = request.json
    json_dict = json.loads(incoming_json)
    username = json_dict['username']
    password = json_dict['password']
    if username is None or password is None:
        abort(400) # missing arguments

    user = User.query.filter_by(username=username).first()

    if not user or not user.verify_password(password):
        abort(401)
    else:
        login_user(user, remember=True)
    return 'login'

@app.route('/delete_account')
@login_required
def delete_account():
    User.query.filter_by(id=current_user.get_id()).delete()
    db.session.commit()
    logout_user()
    return 'delete'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'logout'

@app.route('/retrieve_new_message',methods=['POST'])
@login_required
def retrieve_new_message():
    incoming_json = request.json
    json_dict = json.loads(incoming_json)
    latest_message_id = json_dict['latest_message_id']
    sender_username = json_dict['sender_username']

    current_username = User.query.filter_by(id=current_user.get_id()).username

    sender_id = User.query.filter_by(username = sender_username).first()

    receiver_id = current_user.get_id()

    messages = Messages.query.filter(Messages.id > latest_message_id).filter(Messages.receiver == receiver_id).filter(Messages.sender == sender_id).all()
    messages2 = Messages.query.filter(Messages.id > latest_message_id).filter(Messages.receiver == sender_id).filter(Messages.sender == receiver_id).all()

    json_list = []

    for message in messages:
        data = {
        'id':message.id,
        'sender':sender_username,
        'message':message.message,
        }
        json_list.append(data)

    for messages2 in messages2:
        data = {
        'id':messages2.id,
        'sender':current_username,
        'message':messages2.message,
        }
        json_list.append(data)

    if(len(json_list)==0):
        abort(404)

    return jsonify(json_list)

@app.route('/send_message',methods=['POST'])
@login_required
def send_message():
    incoming_json = request.json
    json_dict = json.loads(incoming_json)
    receiver_username = json_dict['receiver_username']
    receiver_id = User.query.filter_by(username = receiver_username).first()

    if not receiver_id:
        return 'No Receiver'

    message = json_dict['message']

    if not message:
        return 'Error Empty Message'

    sender_id = current_user.get_id()

    message_insert = Messages(receiver=receiver_id.id,sender=sender_id,message=message)
    db.session.add(message_insert)
    db.session.commit()

    return 'Definetly Worked'


@app.route('/delete_message',methods=['POST'])
@login_required
def delete_message():

    message_id = request.json.get('message_id')
    user_id = current_user.get_id()

    Messages.query.filter_by(id=message_id,sender=user_id).delete()
    db.session.commit()


    return 'Definetly Deleted'

if __name__ == "__main__":
    app.run(debug=True)
