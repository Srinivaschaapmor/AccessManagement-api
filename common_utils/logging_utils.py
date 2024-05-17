import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime
from common_utils.Config import Config
from pymongo import MongoClient
# from common_utils.MongodbHandler import MongoDBHandler

logger = None


if not os.path.exists(Config.logs_folder):
    os.makedirs(Config.logs_folder)

def setup_logger():

    global logger

    # Check if the logger is already set up
    if logger is not None:
        return logger

    # Create a logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    # Create a formatter
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Create a rotating file handler
    log_file = os.path.join(Config.logs_folder, f"{datetime.now().strftime('%Y-%m-%d')}.log")
    handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
    handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(handler)

    # mongo_handler = MongoDBHandler()
    # mongo_handler.setLevel(logging.INFO)
    # mongo_handler.setFormatter(formatter)
    # logger.addHandler(mongo_handler)

    return logger