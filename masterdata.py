from flask import request, jsonify, Blueprint
from common_utils.logging_utils import setup_logger
from models import Model
import uuid
from config import MasterdataConfig
from pymongo import ASCENDING, errors
from auth_token import token_required
from pymongo.errors import DuplicateKeyError

masterdata_routes = Blueprint('masterdatas_routes', __name__)

logger = setup_logger()
masterdata_collection=MasterdataConfig.get_category_collection()
# masterdata_collection.create_index([('Id',ASCENDING)], unique=True)

@masterdata_routes.route('/masterdata', methods=['GET'])
@token_required
def get_masterdata(**kwargs):
    """
    Get a list of masterdata
    ---
    parameters:
      - name: Authorization
        in: header
        required: true
    responses:
      200:
        description: A list of masterdata
      403:
        description: permission denied    
      500:
        description: Internal Server Error Occurred
    """
    try:
        uploader_role = kwargs.get('uploader_role')
        if not uploader_role or 'Admin' not in uploader_role:
            return jsonify({'message': 'Permission denied'}), 403
        
        logger.info('Fetching masterdata')
        users = list(masterdata_collection.find({}))
        for user in users:
            user['_id'] = str(user['_id'])
        return jsonify(users), 200
    except Exception as e:
        logger.error('Error fetching masterdata: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500
    
   
@masterdata_routes.route('/masterdata/<string:category>', methods=['GET'])
@token_required
def get_masterdata_by_category(category, **kwargs):
    """
    Get the masterdata by category
    ---
    parameters:
      - name: Authorization
        in: header
        required: true
      - name: category
        in: path
        description: Category to retrieve details
        required: true
        type: string
    responses:
      200:
        description: Category details retrieved successfully
      403:
        description: permission denied  
      404:
        description: Category not found
      500:
        description: Internal server error
    """
    try:
        uploader_role = kwargs.get('uploader_role')
        if not uploader_role or 'Admin' not in uploader_role:
            return jsonify({'message': 'Permission denied'}), 403
        
        logger.info('Fetching masterdata by category: %s', category)
        masterdata = masterdata_collection.find({'category': category}, {'label': 1, '_id': 0})
        
        user_list = []
        for data in masterdata:
            user_list.append(data.get('label'))
        
        if not user_list:
            return jsonify({"error": "Category not found"}), 404
        
        return jsonify(user_list), 200
    
    except Exception as e:
        logger.error('Error fetching details: %s', str(e), exc_info=True)
        return jsonify({"error": "Internal server error occurred"}), 500
    
@masterdata_routes.route('/create_masterdata', methods=['POST'])
@token_required
def create_masterdata(**kwargs):
    """
    Create a masterdata
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
            category:
              type: string
            value:
              type: string
            label:
              type: string
    responses:
      201:
        description: masterdata added successfully
      400:
        description: error in creating masterdata
      403:
        description: permission denied
      500:
        description: internal server error
    """
    try:
        uploader_role = kwargs.get('uploader_role')
        if not uploader_role or 'Admin' not in uploader_role:
            return jsonify({'message': 'Permission denied'}), 403
        
        logger.info('A new master data entry is being added')

        json_data = request.get_json()
        if not json_data:
            return jsonify({'error': 'No data provided'}), 400

        user_data = Model(**json_data)
        
        result = masterdata_collection.insert_one(user_data.dict())
        logger.info('New master data added successfully')
        return jsonify({'message': 'User data added successfully', 'document_id': str(result.inserted_id)}), 201
    except Exception as e:
        logger.error('Error creating user data: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error occurred'}), 500
    

    
@masterdata_routes.route('/create_masterdata_many', methods=['POST'])
@token_required
def create_masterdata_many(**kwargs):
    """
    Create multiple masterdata entries
    ---
    parameters:
      - name: Authorization
        in: header
        required: true
      - name: body
        in: body
        required: true
        schema:
          type: array
          items:
            type: object
            properties:
              category:
                type: string
              value:
                type: string
              label:
                type: string
    responses:
      201:
        description: Multiple masterdata entries added successfully
      400:
        description: Error in creating masterdata entries
      403:
        description: Permission denied
      500:
        description: Internal server error
    """
    try:
        uploader_role = kwargs.get('uploader_role')
        if not uploader_role or 'Admin' not in uploader_role:
            return jsonify({'message': 'Permission denied'}), 403
        
        logger.info('Adding multiple master data entries')

        json_data = request.get_json()
        if not json_data or not isinstance(json_data, list):
            return jsonify({'error': 'No valid data provided'}), 400

        # Validate and insert each entry
        inserted_ids = []
        for data in json_data:
            user_data = Model(**data)
            result = masterdata_collection.insert_one(user_data.dict())
            inserted_ids.append(str(result.inserted_id))

        logger.info('Multiple master data entries added successfully')
        return jsonify({'message': 'Multiple master data entries added successfully', 'inserted_ids': inserted_ids}), 201
    except Exception as e:
        logger.error('Error creating multiple master data entries: %s', str(e), exc_info=True)
        return jsonify({'error': 'Internal server error occurred'}), 500
   

# if __name__=="__main__":
#     masterdata_routes.run(debug=True)    