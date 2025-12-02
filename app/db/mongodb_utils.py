#import logging
from fastapi.logger import logger

from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import MONGODB_URL, MAX_CONNECTIONS_COUNT, MIN_CONNECTIONS_COUNT
from app.db.mongodb import db


async def connect_to_mongo():
    logger.info(f"Connecting to database... {MONGODB_URL}")
    db.client = AsyncIOMotorClient(str(MONGODB_URL),
                                   maxPoolSize=MAX_CONNECTIONS_COUNT,
                                   minPoolSize=MIN_CONNECTIONS_COUNT)
    logger.info("Database connected！")


async def close_mongo_connection():
    logger.info("Closing database connection...")
    db.client.close()
    logger.info("Database closed！")
