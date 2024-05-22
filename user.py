from flask import request, jsonify, Blueprint
from common_utils.logging_utils import setup_logger
from models import UserModel
import uuid
from config import UserConfig
from pymongo import ASCENDING, errors
from flasgger import Swagger
from auth_token import token_required

user_routes = Blueprint('users_routes', __name__)

logger = setup_logger()
user_collection = UserConfig.get_users_collection()
user_collection.create_index([('Id', ASCENDING)], unique=True)

@user_routes.route('/endusers', methods=['GET'])
def get_endusers_list():
    """
    Get a list of all end users
    ---
    responses:
      200:
        description: A list of users
      500:
        description: Internal Server Error Occurred
                   
    """
    try:
        logger.info('Fetching user list')
        users = list(user_collection.find({}, {"_id": 0}))
        return jsonify(users),200
    except Exception as e:
        logger.error('Error fetching user list: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

@user_routes.route('/create_user', methods=['POST'])
def create_users_data(**kwargs):
    """
    Create a user
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
                type: string
    responses:
      201:
        description: User data added successfully
        schema:
          type: object
          properties:
            message:
              type: string
            document_id:
              type: string
      400:
        description: Error in creating user data
      409:
        description: Duplicate user ID
    """
    try:
        uploader_access = kwargs.get('uploader_access')
        if 'Admin' not in uploader_access:
            return jsonify({'message': 'Permission denied'}), 403
        logger.info('A new user data added successfully')
        json_data = request.get_json()
        user_data = UserModel(**json_data)
        user_data.Id = str(uuid.uuid4())
        result = user_collection.insert_one(user_data.dict())
        logger.info('User data created successfully')
        return jsonify({'message': 'User data added successfully', 'document_id': str(result.inserted_id)}), 201
    except errors.DuplicateKeyError:
        logger.error('Duplicate user ID detected: %s', user_data.EmpId)
        return jsonify({'error': 'Duplicate user ID'}), 409
    except Exception as e:
        logger.error('Error creating user data: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error occurred'}), 500

@user_routes.route('/users/update/<string:empid>', methods=['PUT'])
@token_required
def update_user_data(empid, **kwargs):
    """
    Update user information
    ---
    parameters:
      - name: Authorization
        in: header
        required: true
      - name: empid
        in: path
        description: ID of the user to update
        required: true
        type: string
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
            EmployeeType:
              type: string
            Contact:
              type: string
    responses:
      200:
        description: User data updated successfully
        schema:
          type: object
          properties:
            message:
              type: string
      400:
        description: Bad request - Invalid parameters
      404:
        description: User not found
      403:
        description: Permission denied
      500:
        description: Internal server error
    """
    try:
        uploader_access = kwargs.get('uploader_access')
        if 'Admin' not in uploader_access:
            return jsonify({'message': 'Permission denied'}), 403
        logger.info('Updating user data for EmpId: %s', empid)
        json_data = request.get_json()

        user = user_collection.find_one({'EmpId': empid})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        update_data = {
            'FirstName': json_data.get('FirstName'),
            'LastName': json_data.get('LastName'),
            'EmployeeType': json_data.get('EmployeeType'),
            'Contact': json_data.get('Contact')
        }
        user_collection.update_one({'EmpId': empid}, {'$set': update_data})
        return jsonify({'message': 'User data updated successfully'}), 200
    except Exception as e:
        logger.error('Error updating user data: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error occurred'}), 500

@user_routes.route('/users/update/access/<string:empid>', methods=['PUT'])
@token_required
def update_user_access(empid, **kwargs):
    """
    Update user access details (Access, SpaceName)
    ---
    parameters:
      - name: Authorization
        in: header
        required: true
      - name: empid
        in: path
        description: ID of the user to update access details
        required: true
        type: string
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            Access:
              type: array
              items:
                type: string
            SpaceName:
              type: array
              items:
                type: string
    responses:
      200:
        description: User access details updated successfully
        schema:
          type: object
          properties:
            message:
              type: string
      400:
        description: Bad request - Invalid parameters
      404:
        description: User not found
      403:
        description: Permission denied
      500:
        description: Internal server error
    """
    try:
        uploader_access = kwargs.get('uploader_access')
        if 'Admin' not in uploader_access:
            return jsonify({'message': 'Permission denied'}), 403
        logger.info('Updating access details for user with EmpId: %s', empid)
        json_data = request.get_json()

        user = user_collection.find_one({'EmpId': empid})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        existing_space_names = user.get('SpaceName', [])
        new_space_names = json_data.get('SpaceName', [])

        updated_space_names = list(set(existing_space_names + new_space_names))

        update_data = {
            'Access': json_data.get('Access', []),
            'SpaceName': updated_space_names
        }
        user_collection.update_one({'EmpId': empid}, {'$set': update_data})
        return jsonify({'message': 'User details updated successfully'}), 200
    except Exception as e:
        logger.error('Error updating user details: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error occurred'}), 500

@user_routes.route('/users/delete/<string:empid>', methods=['DELETE'])
@token_required
def delete_user(empid, **kwargs):
    """
    Delete a user from users list
    ---
    parameters:
      - name: Authorization
        in: header
        required: true
      - name: empid
        in: path
        description: ID of the user to delete
        required: true
        type: string
    responses:
      200:
        description: User deleted successfully
        schema:
          type: object
          properties:
            message:
              type: string
      400:
        description: Bad request - Invalid parameters
      404:
        description: User not found in the users list
      500:
        description: Internal server error
    """
    try:
        result = user_collection.delete_one({"EmpId": empid})
        if result.deleted_count == 1:
            logger.info('User with EmpId %s deleted successfully', empid)
            return jsonify({"message": "User data deleted successfully"}), 200
        else:
            logger.warning('User with EmpId %s not found', empid)
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        logger.error('An error occurred: %s', str(e), exc_info=True)
        return jsonify({"message": "An error occurred while deleting user data"}), 500
