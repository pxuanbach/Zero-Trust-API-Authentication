"""
Redis cache implementation for proxy
"""
import json
import asyncio
from typing import Optional
import redis.asyncio as redis
from ...shared.interfaces import ICacheProvider


class RedisCache(ICacheProvider):
    """Redis implementation of cache provider"""
    
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis_client: Optional[redis.Redis] = None
    
    async def connect(self):
        """Initialize Redis connection"""
        try:
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            # Test connection
            await self.redis_client.ping()
            print(f"Connected to Redis at {self.redis_url}")
        except Exception as e:
            print(f"Failed to connect to Redis: {str(e)}")
            raise
    
    async def disconnect(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
    
    async def get(self, key: str) -> Optional[str]:
        """Get value from Redis cache"""
        try:
            if not self.redis_client:
                await self.connect()
            return await self.redis_client.get(key)
        except Exception as e:
            print(f"Redis GET error: {str(e)}")
            return None
    
    async def set(self, key: str, value: str, expire_seconds: Optional[int] = None) -> bool:
        """Set value in Redis cache with optional expiration"""
        try:
            if not self.redis_client:
                await self.connect()
            
            if expire_seconds:
                return await self.redis_client.setex(key, expire_seconds, value)
            else:
                return await self.redis_client.set(key, value)
        except Exception as e:
            print(f"Redis SET error: {str(e)}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from Redis cache"""
        try:
            if not self.redis_client:
                await self.connect()
            result = await self.redis_client.delete(key)
            return result > 0
        except Exception as e:
            print(f"Redis DELETE error: {str(e)}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in Redis cache"""
        try:
            if not self.redis_client:
                await self.connect()
            result = await self.redis_client.exists(key)
            return result > 0
        except Exception as e:
            print(f"Redis EXISTS error: {str(e)}")
            return False
    
    async def set_json(self, key: str, value: dict, expire_seconds: Optional[int] = None) -> bool:
        """Set JSON object in cache"""
        try:
            json_str = json.dumps(value)
            return await self.set(key, json_str, expire_seconds)
        except Exception as e:
            print(f"Redis SET JSON error: {str(e)}")
            return False
    
    async def get_json(self, key: str) -> Optional[dict]:
        """Get JSON object from cache"""
        try:
            json_str = await self.get(key)
            if json_str:
                return json.loads(json_str)
            return None
        except Exception as e:
            print(f"Redis GET JSON error: {str(e)}")
            return None


class MemoryCache(ICacheProvider):
    """In-memory cache implementation for testing/development"""
    
    def __init__(self):
        self._cache = {}
        self._expiry = {}
    
    async def get(self, key: str) -> Optional[str]:
        """Get value from memory cache"""
        if key in self._expiry:
            import time
            if time.time() > self._expiry[key]:
                await self.delete(key)
                return None
        
        return self._cache.get(key)
    
    async def set(self, key: str, value: str, expire_seconds: Optional[int] = None) -> bool:
        """Set value in memory cache with optional expiration"""
        try:
            self._cache[key] = value
            if expire_seconds:
                import time
                self._expiry[key] = time.time() + expire_seconds
            return True
        except Exception:
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from memory cache"""
        try:
            if key in self._cache:
                del self._cache[key]
            if key in self._expiry:
                del self._expiry[key]
            return True
        except Exception:
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in memory cache"""
        if key in self._expiry:
            import time
            if time.time() > self._expiry[key]:
                await self.delete(key)
                return False
        
        return key in self._cache