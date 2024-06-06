from flask import request, jsonify, Blueprint
from common_utils.logging_utils import setup_logger
from models import UserModel
import uuid
from config import UserConfig
from pymongo import ASCENDING, errors
from flasgger import Swagger
from auth_token import token_required
from functools import wraps
import jwt as jwt_module

from flask_cors import CORS
from bson import ObjectId

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
        users = list(user_collection.find({}))
        for user in users:
            user['_id'] = str(user['_id'])
        return jsonify(users), 200
    except Exception as e:
        logger.error('Error fetching user list: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

@user_routes.route('/users/access/<string:empid>', methods=['GET'])
def get_access_details_by_empid(empid):
    """
    Get enduser access details by empid
    ---
    parameters:
      - name: empid
        in: path
        description: ID of the user to retrieve access details
        required: true
        type: string
    responses:
      200:
        description: Access details retrieved successfully
      404:
        description: User not found
      500:
        description: Internal server error
    """
    try:
        logger.info('Fetching user access details for empid: %s', empid)
        empid=ObjectId(empid)
        user = user_collection.find_one({'_id': empid}, {'_id': 1,'Access': 1})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        user['_id'] = str(user['_id'])

        return jsonify(user), 200
    except Exception as e:
        logger.error('Error fetching user access details: %s', str(e), exc_info=True)
        return jsonify({"error": "Internal server error occurred"}), 500

@user_routes.route('/users_with_access', methods=['GET'])
def get_users_details_who_has_access():
    """
    Get details of users who has access
    ---
    responses:
      200:
        description: A list of accessed users
      404:
        description: No users found with access
      500:
        description: Internal server error
    """
    try:
        logger.info('Fetching users with access')
        query = {'Access': {'$ne': []}}
        users = list(user_collection.find(query))

        if not users:
            return jsonify({"error": "No users found with access"}), 404
        
        for user in users:
            user['_id'] = str(user['_id'])

        return jsonify(users), 200
    except Exception as e:
        logger.error('Error fetching accessed user list: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500

@user_routes.route('/create_user', methods=['POST'])
@token_required
def create_users_data(**kwargs):
    """
    Create a user
    ---
    parameters:
      - name: Authorization
        in: header
        required: true
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
              type: string  
            Access:    
              type: array
              items:
                type: string
            Role:
              type: string    
    responses:
      201:
        description: User data added successfully
      400:
        description: Error in creating user data
      403:
        description: Permission denied  
      409:
        description: Duplicate user ID
      500:
        description: Internal server error  
    """
    try:
        uploader_role = kwargs.get('uploader_role')
        if 'Admin' not in uploader_role:
            return jsonify({'message': 'Permission denied'}), 403
        logger.info('A new user data added successfully')

        json_data = request.get_json()
        json_data['Role'] = "User"
        json_data['Access'] = []
        # print("DATA", json_data)
        user_data = UserModel(**json_data)
        
        user_data.Id = str(uuid.uuid4())
        result = user_collection.insert_one(user_data.dict())
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
            EmpId:
              type: string
            Email:
              type: string    
            EmployeeType:
              type: string
            Contact:
              type: string
            JobTitle:
              type: string
            SpaceName:
              type: string    
    responses:
      200:
        description: User data updated successfully
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
        uploader_role = kwargs.get('uploader_role')
        if 'Admin' not in uploader_role:
            return jsonify({'message': 'Permission denied'}), 403

        logger.info('Updating user data for EmpId: %s', empid)
        json_data = request.get_json()
        empid=ObjectId(empid)

        user = user_collection.find_one({'_id': empid})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        update_data = {
            'FirstName': json_data.get('FirstName'),
            'LastName': json_data.get('LastName'),
            'EmpId':json_data.get('EmpId'),
            'Contact': json_data.get('Contact'),
            'Email':json_data.get('Email'),
            'JobTitle':json_data.get('JobTitle'),
            'EmployeeType': json_data.get('EmployeeType'),
            'SpaceName':json_data.get('SpaceName')

        }
        user_collection.update_one({'_id': empid}, {'$set': update_data})
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
              type: string
    responses:
      200:
        description: User access details updated successfully
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
        uploader_role = kwargs.get('uploader_role')
        if 'Admin' not in uploader_role:
            return jsonify({'message': 'Permission denied'}), 403

        logger.info('Updating access details for user with EmpId: %s', empid)
        json_data = request.get_json()
        empid=ObjectId(empid)

        user = user_collection.find_one({'_id': empid})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        existing_access = user.get('Access', [])
        new_access = json_data.get('Access', [])
        # print("json_data", request.json)
        # print("existing_space_names", existing_access)
        # print("new_space_names", new_access)
        updated_access = list(set(existing_access + new_access))
        # print("updated_access", updated_access)
        update_data = {
            'Access': updated_access,
            'SpaceName': json_data.get('SpaceName', [])
        }
        user_collection.update_one({'_id': empid}, {'$set': update_data})
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
        uploader_role = kwargs.get('uploader_role')
        if 'Admin' not in uploader_role:
            return jsonify({'Message': 'Permission denied'}), 403
        logger.info("Deleting EmpId %s", empid)
        empid=ObjectId(empid)

        result = user_collection.delete_one({"_id": empid})
        if result.deleted_count == 1:
            logger.info('User with EmpId %s deleted successfully', empid)
            return jsonify({"message": "User deleted successfully"}), 200
        else:
            logger.warning('User with EmpId %s not found', empid)
            return jsonify({"message": "User not found"}), 404
    except Exception as e:
        logger.error('An error occurred: %s', str(e), exc_info=True)
        return jsonify({"message": "An error occurred while deleting user data"}), 500

@user_routes.route('/users/delete/access/<string:empid>/<string:access>', methods=['DELETE'])
@token_required
def delete_access_from_user(empid, access, **kwargs):
    """
    Delete an access from a user's access list
    ---
    parameters:
      - name: Authorization
        in: header
        required: true
      - name: empid
        in: path
        description: id of the user whose access needs to be deleted
        required: true
        type: string
      - name: access
        in: path
        description: access to be deleted from the user's access list
        required: true
        type: string
    responses:
      200:
        description: Access deleted successfully
      400:
        description: Bad request - invalid parameters
      401:
        description: Unauthorized  
      404:
        description: User not found or access not found in the user's access list
      500:
        description: Internal server error
    """
    try:
        uploader_role = kwargs.get('uploader_role')
        if 'Admin' not in uploader_role:
            return jsonify({'Message': 'Permission denied'}), 403
        logger.info("Deleting access '%s' from user with EmpId '%s'", access, empid)
        empid=ObjectId(empid)

        user = user_collection.find_one({'_id': empid})
        if not user:
            return jsonify({"error": 'User not found'}), 404

        access_names = user.get('Access', [])

        if access not in access_names:
            return jsonify({"error": "Access not found in user's access list"}), 404

        access_names.remove(access)

        user_collection.update_one({'_id': empid}, {'$set': {'Access': access_names}})
        return jsonify({'Message': f"Access '{access}' deleted successfully"}), 200
    except Exception as e:
        logger.error('Error deleting access of user: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error occurred'}), 500
