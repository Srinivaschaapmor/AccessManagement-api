import logging
from datetime import datetime
# from organization.config import apilogsconfig
from flask import request

class MongoDBHandler(logging.Handler):
    def __init__(self,collection_name='API-logs'):
        super().__init__()
        self.collection_name = collection_name
        self.collection=apilogsconfig.get_apilogs_collection()
    def emit(self,record):
        ip_address=request.remote_addr
        UserAgent=request.headers.get('User-Agent')

        error_message=self.format(record) if record.levelname in ['WARNING','ERROR']else None
        log_entry = {
            "timestamp":datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S'),
            "level":record.levelname,
            "message":self.format(record),
            "ip_address":ip_address,
            "UserAgent":UserAgent,
            "ErrorMessage":error_message
        }
        self.collection.insert_one(log_entry)