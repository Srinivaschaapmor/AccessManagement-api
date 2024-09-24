from flask import Flask, Blueprint, request, jsonify
from datetime import datetime
from flask_mail import Mail, Message
import random
import string
from config import LoginConfig, UserLogin,tenantConfig
import re
from flasgger import Swagger, swag_from  # Import swag_from from flasgger
from common_utils.logging_utils import setup_logger
from pymongo import MongoClient
import jwt as jwt_module
from flask_cors import CORS
import json
import os

# Create a Flask app
otp_routes = Blueprint('otp_routes', __name__)
selectDB_routes = Blueprint('selectDB_routes', __name__)
logger = setup_logger()
mail = Mail()

def generate_otp():
    # Randomly generating OTP
    otp = ''.join(random.choices(string.digits, k=6))
    otp_timestamp = datetime.now()
    return otp, otp_timestamp

def is_valid_email(email):
    # Using regular expression checking whether the email is valid or not
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(regex, email))

@otp_routes.route('/login/send-otp', methods=['POST'])
@swag_from({
    'description': 'Endpoint to send OTP to the provided email address.',
    'parameters': [{
        'in': 'body',
        'name': 'email',
        'description': 'The email address where the OTP will be sent.',
        'required': True,
        'schema': {
            'type': 'object',
            'properties': {
                'email': {
                    'type': 'string'
                }
            }
        }
    }],
    'responses': {
        '201': {
            'description': 'A Message indicating that the OTP has been sent successfully.',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        '400': {
            'description': 'Invalid email address provided.',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '500': {
            'description': 'Internal server error occurred.',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def send_otp():
    try:
        data = request.get_json()
        recipient = data.get('email')
        
        if not is_valid_email(recipient):
            logger.error('Invalid email address provided: %s', recipient)
            return jsonify({'error': 'Invalid email address provided'}), 400
        
        msg = Message('Your OTP', sender='aapmorblogs@gmail.com', recipients=[recipient])
        otp, otp_timestamp = generate_otp()
        collection = LoginConfig.get_login_details()
        ip_address = request.remote_addr

        # Insert data into MongoDB collection
        result = collection.insert_one({'email': recipient, 'otp': otp, 'timestamp': otp_timestamp, 'ip_address': ip_address})

        if result.inserted_id:
            msg.body = f"Dear {recipient},\n\nYour OTP is: {otp}\n\nPlease use this code within the next 2 minutes to complete the login process. If you didn't request this OTP or if you encounter any issues, please contact our support team immediately."
            mail.send(msg)
            logger.info('OTP sent successfully to %s', recipient)
            return jsonify({'message': 'OTP sent successfully'}), 201
        else:
            logger.error('Failed to insert OTP data into MongoDB')
            return jsonify({'error': 'Failed to insert OTP data into MongoDB'}), 500
    except Exception as e:
        logger.error('Error sending OTP: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error occurred'}), 500
    
@otp_routes.route('/login/verify-otp', methods=['POST'])
@swag_from({
    'description': 'Endpoint to verify OTP and provide a JWT token upon successful verification.',
    'parameters': [{
        'in': 'body',
        'name': 'email',
        'description': 'The OTP received by the user.',
        'required': True,
        'schema': {
            'type': 'object',
            'properties': {
                'otp': {'type': 'string'},
                'email': {'type': 'string'}
            }
        }
    }],
    'responses': {
        '201': {
            'description': 'A message indicating successful OTP verification and JWT token.',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'jwt_token': {'type': 'string'}
                }
            }
        },
        '400': {
            'description': 'Invalid OTP provided or OTP expired.',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '500': {
            'description': 'Internal server error occurred.',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def verify_otp():
    try:
        data = request.get_json()
        if not data:
            logger.warning('Request data is missing')
            return jsonify({'error': 'Request data is missing'}), 400

        otp_received = data.get('otp')
        email = data.get('email')

        if not otp_received or not email:
            logger.warning('Email or OTP missing in the request')
            return jsonify({'error': 'Email or OTP missing in the request'}), 400

        collection = LoginConfig.get_login_details()
        logindata = collection.find_one({'email': email, 'otp': otp_received})

        if not logindata:
            logger.warning('Email not found in login details: %s', email)
            return jsonify({'error': 'Invalid OTP'}), 401

        correct_otp = logindata['otp']
        correct_otp_timestamp = logindata['timestamp']

        if (datetime.now() - correct_otp_timestamp).total_seconds() > 120:
            logger.warning('OTP verification failed: OTP expired for %s', email)
            return jsonify({'error': 'OTP expired. Please request a new one.'}), 410

        if otp_received == correct_otp:
            logger.info('OTP verification successful for %s', email)

            user_data = UserLogin.get_user_data(email)
            if not user_data:
                return jsonify({'error': 'User data not found'}), 400

            user_access = user_data.get("Access",[])
            user_access = [str(Access) for Access in user_access]
            # print("userAccess",user_access)

            payload = {
                'Id': user_data.get('Id'),
                'EmpId': user_data.get('EmpId'),
                'FirstName': user_data.get('FirstName'),
                'Access': user_access,
                'SpaceName': user_data.get('SpaceName'),
                'Role': user_data.get('Role'),  
                'AdminRoles':user_data.get('AdminRoles'),
                'FullName':user_data.get('FullName'),
                'NexusSuperAdmin' : user_data.get('NexusSuperAdmin'),
                'OrgxSuperAdmin':user_data.get('OrgxSuperAdmin'),
                'Uid':user_data.get('Uid')

            }
            secret_key = 'St@and@100ardapi@aap100mor#100'
            encoded_jwt = jwt_module.encode(payload, secret_key, algorithm='HS256')

            if isinstance(encoded_jwt, bytes):
                encoded_jwt = encoded_jwt.decode('utf-8')

            logger.info('Generated JWT token: %s', encoded_jwt)
            return jsonify({
                'message': 'OTP verification successful. Login successful.',
                'jwt_token': encoded_jwt,
                'userEmail': user_data.get("Email"),
                'access': user_access
            }), 201
        else:
            logger.warning('Invalid OTP provided: %s', otp_received)
            return jsonify({'error': 'Invalid OTP'}), 401
    except Exception as e:
        logger.error('Internal server error occurred: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error occurred'}), 500
    

def write_tenant_to_file(tenant):
    file_path = 'tenant_details.json'
    with open(file_path, 'w') as f:
        json.dump(tenant, f)

@selectDB_routes.route('/connect/database', methods=['POST'])
@swag_from({
    'description': 'Endpoint to send OTP to the provided email address.',
    'parameters': [{
        'in': 'body',
        'name': 'email',
        'description': 'The email address where the OTP will be sent.',
        'required': True,
        'schema': {
            'type': 'object',
            'properties': {
                'email': {
                    'type': 'string'
                }
            }
        }
    }],
    'responses': {
        '201': {
            'description': 'A Message indicating that the OTP has been sent successfully.',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        '400': {
            'description': 'Invalid email address provided.',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        '500': {
            'description': 'Internal server error occurred.',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def connect_DB():
    try:
        data = request.get_json()
        subdomain = data.get('subdomain')

        if not(subdomain):
            logger.error('Invalid Domain provided: %s', subdomain)
            return jsonify({'error': 'Invalid Domain provided'}), 400
        
        collection = tenantConfig.get_tenant_collection()
        tenant = collection.find_one({'tenant_name':subdomain})
        tenant_email_template = tenant.get('email_template')
        response = {
            "tenant_id": tenant.get('tenant_id'),
            "tenant_name": tenant.get('tenant_name'),
            "Open_AI_config": tenant.get('Open_AI_config'),
            "tenant_Platfrom_DB": tenant.get('tenant_Platfrom_DB'),
            "tenant_AI_DB": tenant.get('tenant_AI_DB'),
            "Azure_blob_config": tenant.get('Azure_blob_config')
        }
        write_tenant_to_file(response)
        

        if tenant:
            # print("Tenant found:", tenant)
            return jsonify({'message': 'Tenant found', 'tenant': response}), 200
        else:
            logger.error('Tenant not found for subdomain: %s', subdomain)
            return jsonify({'error': 'Tenant not found'}), 404

    except Exception as e:
        logger.error('Error occurred while connecting to the DB: %s', str(e))
        return jsonify({'error': 'Internal server error'}), 500