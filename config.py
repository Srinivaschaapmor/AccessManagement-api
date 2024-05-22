from pymongo import MongoClient
# from pymongo.errors import ConfigurationError


class UserConfig:
    @staticmethod
    def get_mongo_client():
        client = MongoClient('mongodb+srv://nexus-360-dev-user:tgaiqVncYpj6vOpz@nexus-360-dev.6tgnxqq.mongodb.net/')
        return client

    @staticmethod
    def get_database():
        client = UserConfig.get_mongo_client()
        db = client['standard_api']
        return db

    @staticmethod
    def get_users_collection():
        db = UserConfig.get_database()
        collection = db['users']
        return collection
    
class LoginConfig:
    @staticmethod
    def get_mongo_client():
        client = MongoClient('mongodb+srv://nexus-360-dev-user:tgaiqVncYpj6vOpz@nexus-360-dev.6tgnxqq.mongodb.net/')
        return client 
    @staticmethod
    def get_database():
        client = LoginConfig.get_mongo_client()
        db= client['standard_api']
        return db
    @staticmethod
    def get_login_details():
        db = LoginConfig.get_database()
        collection = db['login_logfiles']
        return collection    
    
class UserLogin:
    @staticmethod
    def get_mongo_client():
        client = MongoClient('mongodb+srv://nexus-360-dev-user:tgaiqVncYpj6vOpz@nexus-360-dev.6tgnxqq.mongodb.net/')
        return client

    @staticmethod
    def get_database():
        client = UserLogin.get_mongo_client()
        db = client['standard_api']
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
