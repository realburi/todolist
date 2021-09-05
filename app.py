"""Todo list app backend"""
from flask import Flask, request, jsonify
import jwt
import time
from functools import wraps
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'supersecret'
app.config['SECRET_KEY_REFRESH'] = 'myRefreshSecretKey'
# refresh token list for authentication purposes
refresh_tokens = list()


# decorator for checking bearer token provided in requests
def verify(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        try:
            jwt.decode(
                jwt=request.headers.get('Authorization').replace('Bearer ', ''),
                algorithms=['HS256'],
                key=app.config['SECRET_KEY']
            )
        except Exception as error:
            print(error)
            return jsonify({
                'message': "token not valid"
            }), 401
        return func(*args, **kwargs)
    return decorated


# demo users
users = [
    {
        'id': 1,
        'name': "John",
        'password': "John0908",
        'isAdmin': True
    },
    {
        'id': 2,
        'name': "Buri",
        'password': "Buri1127",
        'isAdmin': False
    }
]


def generate_access_token(entry):
    return jwt.encode(
        algorithm='HS256',
        key=app.config['SECRET_KEY'],
        payload={
            'id': entry.get('id'),
            'isAdmin': entry.get('isAdmin'),
            'iat': round(time.time()),
            'exp': round(time.time() + 30)
        }
    )


def generate_refresh_token(entry):
    refresh = jwt.encode(
        algorithm='HS256',
        key=app.config['SECRET_KEY_REFRESH'],
        payload={
            'id': entry.get('id'),
            'isAdmin': entry.get('isAdmin'),
            'iat': round(time.time()),
            'exp': round(time.time() + 30 * 60)
        }
    )
    return refresh


@app.route('/login', methods=['POST'])
def hello_world():
    username, password = request.get_json().get('username'), request.get_json().get('password')
    print(username, password)
    for entry in users:
        if entry.get('name') == username and entry.get('password') == password:
            access_token = generate_access_token(entry)
            refresh_token = generate_refresh_token(entry)
            refresh_tokens.append(refresh_token)

            return jsonify({
                "username": username,
                "isAdmin": entry.get('isAdmin'),
                "accessToken": access_token,
                "refreshToken": refresh_token
            }), 200

    return 'incorrect', 403


@app.route('/users/<int:user_id>', methods=['DELETE'])
@verify
def delete_user(user_id):
    decoded_token = jwt.decode(
        jwt=request.headers.get('Authorization').replace('Bearer ', ''),
        algorithms=['HS256'],
        key=app.config['SECRET_KEY']
    )
    if decoded_token.get(id) == user_id or decoded_token.get('isAdmin') is True:
        return "User has been deleted", 200
    else:
        return "You are not allowed to delete this user", 403


@app.route('/refresh', methods=['POST'])
def refresh_token_endpoint():
    # take refresh token from user
    token = request.get_json().get('token')
    # send error if token not valid or no token
    if not token:
        return "Token not provided or not authenticated", 401
    if token not in refresh_tokens:
        return "refresh token is not valid", 403
    try:
        decoded_refresh_token = jwt.decode(jwt=token, key=app.config['SECRET_KEY_REFRESH'], algorithms=['HS256'])
        refresh_tokens.remove(token)
        # create new access token
        new_access_token = generate_access_token(decoded_refresh_token)
        new_refresh_token = generate_refresh_token(decoded_refresh_token)
        refresh_tokens.append(new_refresh_token)
    except Exception as error:
        print(error)
    else:
        return jsonify({
            'accessToken': new_access_token,
            'refreshToken': new_refresh_token
        }), 200


@app.route('/logout', methods=['POST'])
@verify
def logout():
    refresh_token = request.get_json().get('token')
    refresh_tokens.remove(refresh_token)
    return jsonify("logged out successfully"), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

