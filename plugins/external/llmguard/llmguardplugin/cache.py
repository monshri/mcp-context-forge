import os
import redis
import pickle

redis_host = os.getenv("REDIS_HOST", "redis")
redis_port = int(os.getenv("REDIS_PORT", 6379))

from mcpgateway.services.logging_service import LoggingService
# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)


class CacheTTLDict(dict):
    def __init__(self, ttl: int = 0):
        self.cache_ttl = ttl
        self.cache = redis.Redis(host=redis_host, port=redis_port)
        logger.info(f"Cache Initialization: {self.cache}")

    def update_cache(self, key, value):
        serialized_obj = pickle.dumps(value)
        logger.info(f"Update cache in cache: {key} {serialized_obj}")
        self.cache.set(key,serialized_obj)
        self.cache.expire(key,self.cache_ttl)
        logger.info(f"Cache updated: {self.cache}")

    def retrieve_cache(self, key):
        value = self.cache.get(key)
        if value:
            retrieved_obj = pickle.loads(value)
        logger.info(f"Cache retrieval for id: {key} with value: {retrieved_obj}")
        return retrieved_obj
    
    def delete_cache(self,key):
        logger.info(f"deleting cache")
        deleted_count = self.cache.delete(key)
        if deleted_count == 1 and self.cache.exists(key) == 0:
            logger.info(f"Cache deleted successfully for key: {key}")
        else:
            logger.info(f"Unsuccessful cache deletion: {key}")

