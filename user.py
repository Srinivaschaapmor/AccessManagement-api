from flask import Flask, request, jsonify
from common_utils.logging_utils import setup_logger
from models import UserModel
import uuid
from config import UserConfig
from pymongo import ASCENDING, errors
from flasgger import Swagger

user_routes = Flask(__name__)
swagger = Swagger(user_routes)

logger = setup_logger()
user_collection = UserConfig.get_users_collection()
user_collection.create_index([('Id', ASCENDING)], unique=True)

# define route for creating user
@user_routes.route('/create_user', methods=['POST'])
def create_users_data(**kwargs):
    """
    create a user
    ---
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            FirstName:
              type: string
            LastName:
              type: string
            EmpId:
              type: string
            Contact:
              type: string
            Email:
              type: string
            JobTitle:
              type: string
            EmployeeType:
              type: string
            SpaceName:
              type: array
              items:
                type: string  
            Access:    
              type: array
              items:
                type: object
                properties:
                  name:
                    type: string
                  access:
                    type: string
    responses:
      201:
        description: user data added successfully
      400:
        description: error in creating user data
      409:
        description: duplicate user id
    """
    try:
        # uploader_access=kwargs.get(uploader_access)
        # if 'approved' not in uploader_access:
        #     return jsonify({'message':'permission denied'}),403
        
        logger.info('a new user data added successfully')
        json_data = request.get_json()
        user_data = UserModel(**json_data)
        user_data.Id = str(uuid.uuid4())
        result = user_collection.insert_one(user_data.dict())
        logger.info('user data created successfully')
        return jsonify({'message': 'user data added successfully', 'document_id': str(result.inserted_id)}), 201
    except errors.DuplicateKeyError:
        logger.error('duplicate user id detected: %s', user_data.EmpId)
        return jsonify({'error': 'duplicate user id'}), 409
    except Exception as e:
        logger.error('error creating user data: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error occurred'}), 500


if __name__ == "__main__":
    user_routes.run(debug=True)
