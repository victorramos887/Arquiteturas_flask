from flask import Blueprint, request, jsonify
from .constants.http_status_codes import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_409_CONFLICT, HTTP_201_CREATED
from .database import User, db
import validators
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token

auth = Blueprint("auth", __name__, url_prefix="/api/v1/auth")



@auth.post('/register')
def register():

    #pegar os valores do 'post'
    username = request.json['username']
    email = request.json['email']
    password = request.json['password']

    #VERIFICANDO O COMPRIMENTO DA SENHA
    if len(password) < 6:
        return jsonify({'error':'Password is too short'}), HTTP_400_BAD_REQUEST

    #VERIFICANDO O TAMANHO DO USUÁRIO
    if len(username) < 3:
        return jsonify({'error':'User is too short'}), HTTP_400_BAD_REQUEST

    if not username.isalnum() or " " in username:
        return jsonify({'error':'Username should be alphabetic, also no space'}), HTTP_400_BAD_REQUEST

    if not validators.email(email):
        return jsonify({'error':'Email is not valid'}), HTTP_400_BAD_REQUEST

    if User.query.filter_by(email=email).first() is not None:
        return jsonify({'error':'Email is taken'}), HTTP_409_CONFLICT

    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'error':'Username is taken'}), HTTP_409_CONFLICT

    pwd_hash = generate_password_hash(password)

    user = User(username=username, password=pwd_hash, email=email)
    db.session.add(user)
    db.session.commit()

    return jsonify({
        'mensagem':'User Created',
        'user' : {
            'username':username, 'email':email
        }
    }), HTTP_201_CREATED



@auth.post('/login')
def login():
    email = request.json.get('email', '')
    password = request.json.get('password', '')

    # with User.query.filter_by(email=email).first() as user:
    #     if user and check_password_hash(user.password, password):
    #         refresh = create_refresh_token(identity=user.id)
    #         access = create_access_token(identity=user.id)
    #         return jsonify({
    #             'user': {
    #                 'refresh':refresh,
    #                 'access':access,
    #                 'username':user.username,
    #                 'email':user.email
    #             }
    #         })
    
    user = User.query.filter_by(email=email).first()
    if user:
        check = check_password_hash(user.password, password)
        if check:
            refresh = create_refresh_token(identity=user.id)
            access = create_access_token(identity=user.id)
            return jsonify({
                'user': {
                    'refresh':refresh,
                    'access':access,
                    'username':user.username,
                    'email':user.email
                }
            })

    return jsonify({'error':'Wrong credentials'}), HTTP_401_UNAUTHORIZED

@auth.get('/me')
def me():
    return {"user":"me"}
