from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps


app = Flask(__name__)

# Adding config
app.config['SECRET_KEY'] = 'thisismysecret'
# Please add your db path
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'sqlite:////Users/dine2956/Dinesh/Dev/Flask/myflask/contacts.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Contacts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50))
    lastname = db.Column(db.String(50))
    emailid = db.Column(db.String(50))
    phone = db.Column(db.Integer)
    user_id = db.Column(db.Integer)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'X-Auth-Token' in request.headers:
            token = request.headers['X-Auth-Token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {
            'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {
            'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
            'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(
                minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {
        'WWW-Authenticate': 'Basic realm="Login required!"'})


@app.route('/user', methods=['POST'])
def create_user():
    # if not current_user.admin:
    #     return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(
        public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created!'})


# POST - /contact data: {Firstname}
@app.route('/contact', methods=['POST'])
@token_required
def create_contact(current_user):
    data = request.get_json()

    new_contact = Contacts(firstname=data['First Name'],
                           lastname=data['Last Name'],
                           emailid=data['Email Id'],
                           phone=data['Phone'],
                           user_id=current_user.id)
    db.session.add(new_contact)
    db.session.commit()

    return jsonify({'message': "Contact created!"})


# GET - /contact/<string:name>
@app.route('/contacts/<string:name>')  # http://127.0.0.1:5000/contact/<name>
@token_required
def get_contact(current_user, name):

    contacts = Contacts.query.filter_by(user_id=current_user.id, firstname=name).first()

    if not contacts:
        return jsonify({'message': 'Contact not found!'})

    contact_data = {}
    contact_data['id'] = contacts.id
    contact_data['firstname'] = contacts.firstname
    contact_data['lastname'] = contacts.lastname
    contact_data['emailid'] = contacts.emailid
    contact_data['phone'] = contacts.phone

    return jsonify({'contacts': contact_data})


# GET - /contacts
#@app.route('/contacts')
@token_required
# def list_contacts(current_user):

#     contacts = Contacts.query.filter_by(user_id=current_user.id).all()
#     output = []

#     for contact in contacts:
#         contact_data = {}
#         contact_data['id'] = contact.id
#         contact_data['firstname'] = contact.firstname
#         contact_data['lastname'] = contact.lastname
#         contact_data['emailid'] = contact.emailid
#         contact_data['phone'] = contact.phone
#         output.append(contact_data)

#     return jsonify({'contacts': contact_data})

@app.route('/contacts')
def list_contacts(current_user):
    return "No Contact"

# GET - /users
@app.route('/users')
def list_userss():
    return "No users"


# PUT
@app.route('/contacts/<string:name>', methods=['PUT'])
@token_required
def change_contacts(current_user, name):
    data = request.get_json()

    contacts = Contacts.query.filter_by(
        user_id=current_user.id, firstname=name).first()

    contacts.firstname = data['First Name']
    contacts.lastname = data['Last Name']
    contacts.emailid = data['Email Id']
    contacts.phone = data['Phone']

    db.session.commit()

    contacts = Contacts.query.filter_by(
        user_id=current_user.id, firstname=data['First Name'],
        lastname=data['Last Name']).first()

    contact_data = {}
    contact_data['id'] = contacts.id
    contact_data['firstname'] = contacts.firstname
    contact_data['lastname'] = contacts.lastname
    contact_data['emailid'] = contacts.emailid
    contact_data['phone'] = contacts.phone

    return jsonify({'contacts': contact_data})


# Delete
@app.route('/contacts/<string:name>', methods=['DELETE'])
@token_required
def delete_contacts(current_user, name):

    contacts = Contacts.query.filter_by(
        user_id=current_user.id, firstname=name).first()

    db.session.delete(contacts)
    db.session.commit()

    return jsonify({'message': "Message Got Deleted!!!"})


if __name__ == '__main__':
    app.run(debug=True, port=5000)
