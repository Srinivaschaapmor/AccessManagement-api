from flask import Flask, Blueprint, request, jsonify
from datetime import datetime
from flask_mail import Mail, Message 
import random
import string 
from config import LoginConfig,UserLogin
import re
from flasgger import Swagger, swag_from  # Import swag_from from flasgger
from common_utils.logging_utils import setup_logger
from pymongo import MongoClient
import jwt as jwt_module
from flask_cors import CORS
# Create a Flask app
app = Flask(__name__)
CORS(app)
swagger=Swagger(app)

#from smtp server form full stack
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'aapmorblogs@gmail.com'
app.config['MAIL_PASSWORD'] = 'vzyolkoiczhkmixa'

mail = Mail(app)

otp_routes = Blueprint('otp_routes', __name__)

def generate_otp():
    # randomly generating otp
    otp = ''.join(random.choices(string.digits, k=6))
    otp_timestamp = datetime.now()
    return otp, otp_timestamp

def is_valid_email(email):
    # using regular expression checking whether the email is valid or not
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(regex, email))

logger = setup_logger()

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
                    'message': {'type': 'string'},
                    'otp': {'type': 'string'}
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
        result = collection.insert_one({'email': recipient, 'otp': otp, 'timestamp': otp_timestamp,'ip_address': ip_address})

        if result.inserted_id:
            msg.body = f"Dear {recipient},\n\nYour OTP is: {otp}\n\nPlease use this code within the next 2 minutes to complete the login process. If you didn't request this OTP or if you encounter any issues, please contact our support team immediately."
            mail.send(msg)
            logger.info('OTP sent successfully to %s', recipient)
            return jsonify({'message': 'OTP sent successfully', 'otp': otp}), 201
        else:
            logger.error('Failed to insert OTP data into MongoDB')
            return jsonify({'error': 'Failed to insert OTP data into MongoDB'}), 500
    except Exception as e:
        logger.error('Error sending OTP: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error occurred'}), 500
    
@otp_routes.route('/login/verify_otp',methods=['POST'])
@swag_from({
    'description':'endpoint to send otp to the provided email address.',
    'parameters':[{
        'in':'body',
        'name':'email',
        'description':'the otp received by the user.',
        'required':True,
        'schema':{
            'type':'object',
            'properties':{
                'otp':{'type':'string'},
                'email':{'type':'string'}
            }
        }
    }],
    'responses':{
        '201':{
            'description':'a message indicating successful otp verification and jwt token.',
            'schema':{
                'type':'object',
                'properties':{
                    'message':{'type':'string'},
                    'jwt_token':{'type':'string'}
                }
            }
        },
        '400':{
            'description':'Invalid otp provided or otp expired.',
            'schema':{
                'type':'object',
                'properties':{
                    'error':{'type':'string'}
                }
            }
        },
        '500':{
            'description':'Internal server error occurred.',
            'schema':{
                'type':'object',
                'properties':{
                    'error':{'type':'string'}
                }
            }
        }
    }
})
def verify_otp():
    try:
        data=request.get_json()
        otp_received=data.get('otp')
        email=data.get('email')

        collection=LoginConfig.get_login_details()
        logindata=collection.find_one({'email':email,'otp':otp_received})

        if not logindata:
            logger.warning('email not found in login details:%s',email)
            return jsonify({'error':'invalid otp'}),400
        
        correct_otp=logindata['otp']
        correct_otp_timesatamp=logindata['timestamp']

        if(datetime.now()-correct_otp_timesatamp).total_seconds()>120:
            logger.warning('otp verification failed: otp expired for %s',correct_otp)
            return jsonify({'error':'otp expired.please request a new one.'}),400
        
        if otp_received==correct_otp:
            logger.info('otp verification successful for %s',email)

            user_data=UserLogin.get_user_data(email)

            if not user_data:
                return jsonify({'error':'User data not found'}),400
            
            payload={
                'Id':user_data.get('Id'),
                'EmpId':user_data.get('EmpId'),
                'FirstName':user_data.get('FirstName')
            }
            secret_key='St@and@100ardapi@aap100mor#100'
            encoded_jwt=jwt_module.encode(payload,secret_key,algorithm='HS256')

            logger.info('generated jwt token: %s',encoded_jwt)

            return jsonify({
                'message':'otp verification successful.login successful',
                'jwt_token':encoded_jwt
            }),201
        else:
            logger.warning('Invalid otp provided:%s',otp_received)
            return jsonify({'error':'invalid otp'}),400
    except Exception as e:
        logger.error('Internal server error occurred:%s',exc_info=True)
        return jsonify({'error':'Intenal server error occurred'}),500    

app.register_blueprint(otp_routes)

if __name__ == "__main__":
    app.run(debug=True)