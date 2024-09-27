from pymongo import MongoClient
import os
import json
import logging
# # from pymongo.errors import ConfigurationError

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def read_tenant_from_file():
    file_path = 'tenant_details.json'
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return json.load(f)
    else:
        logger.error('Tenant details file not found')
        return None
tenant_details = read_tenant_from_file()
if tenant_details:
    tenant_Platfrom_DB = tenant_details.get('tenant_Platfrom_DB')
else:
    tenant_Platfrom_DB = os.getenv("TENANT_DB")  # Use an environment variable as fallback
    if not tenant_Platfrom_DB:
        logger.error("Tenant details file missing, and TENANT_DB environment variable is not set.")
        tenant_Platfrom_DB = None  # Handle the case where no DB config is available

class tenantConfig:
    @staticmethod
    def get_mongo_client():
        client = MongoClient(os.getenv("TENANT_DB"))
        return client
    @staticmethod
    def get_database():
        client = tenantConfig.get_mongo_client()
        db = client['tenant']
        return db
    @staticmethod
    def get_tenant_collection():
        db = tenantConfig.get_database()
        collection = db['tenant_configurations']
        return collection


class UserConfig:
    @staticmethod
    def get_mongo_client():
        client = MongoClient(tenant_Platfrom_DB)
        return client

    @staticmethod
    def get_database():
        client = UserConfig.get_mongo_client()
        db = client['auth_db']
        return db

    @staticmethod
    def get_users_collection():
        db = UserConfig.get_database()
        collection = db['users']
        return collection
    
class MasterdataConfig:
    @staticmethod
    def get_mongo_client():
        client=MongoClient(tenant_Platfrom_DB)
        return client
    @staticmethod
    def get_database():
        client=MasterdataConfig.get_mongo_client()
        db=client['auth_db']
        return db
    @staticmethod
    def get_category_collection():
        db=MasterdataConfig.get_database()
        collection=db['masterdata_details']
        return collection  
      
class LoginConfig:
    @staticmethod
    def get_mongo_client():
        client = MongoClient(tenant_Platfrom_DB)
        return client 
    @staticmethod
    def get_database():
        client = LoginConfig.get_mongo_client()
        db= client['auth_db']
        return db
    @staticmethod
    def get_login_details():
        db = LoginConfig.get_database()
        collection = db['login_logfiles']
        return collection    
    
class UserLogin:
    @staticmethod
    def get_mongo_client():
        client = MongoClient(tenant_Platfrom_DB)
        return client

    @staticmethod
    def get_database():
        client = UserLogin.get_mongo_client()
        db = client['auth_db']
        return db

    @staticmethod
    def get_users_collection():
        db = UserLogin.get_database()
        collection = db['users']
        return collection

    @staticmethod
    def get_user_data(email):
        collection = UserLogin.get_users_collection()
        user_data = collection.find_one({'Email': email})
        return user_data
