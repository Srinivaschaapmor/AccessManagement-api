from functools import wraps
from flask import request, jsonify
from config import UserConfig
import jwt

user_collection = UserConfig.get_users_collection()

SECRET_KEY = 'St@and@100ardapi@aap100mor#100'

def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # print("TOKEN:", payload);
        return payload['EmpId'], payload['Access'], payload['Role']
    except jwt.ExpiredSignatureError:
        return None, None, None
    except jwt.InvalidTokenError:
        return None, None, None

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # jwtToken = request.headers.get('Authorization')
        token = request.headers.get('Authorization')
        # token = jwtToken.split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Authorization required'}), 401

        uploader_emp_id, uploader_access, uploader_role = verify_token(token)

        if not uploader_emp_id:
            return jsonify({'message': 'Invalid token'}), 401

        kwargs['uploader_emp_id'] = uploader_emp_id
        kwargs['uploader_access'] = uploader_access
        kwargs['uploader_role'] = uploader_role

        return f(*args, **kwargs)
    return decorated_function
