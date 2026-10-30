import logging
import redis
from app.core.config import settings

logger = logging.getLogger("app")

class RedisClient:
    def __init__(self):
        self._redis = None
        self._initialized = False

    def connect(self):
        if settings.REDIS_URL:
            try:
                self._redis = redis.Redis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=1.0,
                    socket_timeout=1.0
                )
                self._redis.ping()
                logger.info("Connected to Redis successfully.")
            except (redis.ConnectionError, redis.TimeoutError, Exception) as e:
                logger.warning(f"Could not connect to Redis: {e}. Falling back to in-memory/DB operations where applicable.")
                self._redis = None
        else:
            logger.info("No REDIS_URL configured. Falling back to local/DB operations.")
        self._initialized = True

    def get_client(self):
        if not self._initialized:
            self.connect()
        return self._redis

redis_client = RedisClient()
