"""
Authorization cache for stateless header-based authentication.

Caches LDAP authorization results to reduce load on the LDAP server.
Uses the same backend as the session store (memory or Redis).

Includes per-key locking to prevent thundering herd / DOS on LDAP:
- In-memory backend: uses asyncio.Lock (per-process)
- Redis backend: uses distributed SETNX lock (across all workers)
"""

import asyncio
import hashlib
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from nginx_ldap_auth.logging import logger
from nginx_ldap_auth.settings import Settings

settings = Settings()
_USE_REDIS_BACKEND = (
    settings.session_backend == "redis" and settings.redis_url is not None
)

# In-memory cache: key -> (authorized, expires_at)
_cache: dict[str, tuple[bool, float]] = {}

# Per-key locks for in-memory backend with LRU tracking
# Stores: key -> (lock, last_access_time)
_key_locks: dict[str, tuple[asyncio.Lock, float]] = {}
_key_locks_lock = asyncio.Lock()

# Maximum number of locks to keep in memory (prevents unbounded growth)
_MAX_LOCKS = 10_000

# Distributed lock TTL (seconds) - should be longer than typical LDAP query time
_REDIS_LOCK_TTL = 10


def _make_cache_key(username: str, authorization_filter: str | None) -> str:
    """
    Generate cache key from username and filter hash.

    :param username: Username used for the cache key.
    :param authorization_filter: LDAP authorization filter to hash, if present.
    :returns: Cache key for the username and filter combination.
    """
    if authorization_filter is None:
        filter_hash = "none"
    else:
        filter_hash = hashlib.sha256(authorization_filter.encode()).hexdigest()[:16]
    return f"header_auth:{username}:{filter_hash}"


def _get_redis_connection():
    """
    Get Redis connection from the session store.

    Note: This accesses the private ``_connection`` attribute of RedisStore
    to reuse the existing Redis connection rather than creating a separate one.
    This coupling is intentional to avoid managing a second Redis connection,
    but may need updating if starsessions changes its internal implementation.

    :returns: Redis connection instance if available, otherwise ``None``.
    """
    if not _USE_REDIS_BACKEND:
        return None

    from starsessions.stores.redis import RedisStore

    from nginx_ldap_auth.app.main import store

    if not isinstance(store, RedisStore):
        logger.error(
            "cache.redis.backend_mismatch",
            backend=type(store).__name__,
        )
        return None

    connection = store._connection
    if connection is None:
        logger.error("cache.redis.connection_missing")
    return connection


def ensure_redis_connection() -> None:
    """
    Ensure Redis connection is available when configured.

    :raises RuntimeError: Redis backend configured but connection unavailable.
    """
    if not _USE_REDIS_BACKEND:
        return
    if _get_redis_connection() is None:
        msg = "Redis backend configured but connection unavailable"
        logger.error("cache.redis.connection_unavailable")
        raise RuntimeError(msg)


# --- Public API ---


@asynccontextmanager
async def authorization_lock(
    username: str, authorization_filter: str | None
) -> AsyncGenerator[None, None]:
    """
    Acquire a lock for the given username/filter combination.

    For in-memory backend: uses asyncio.Lock (protects within process)
    For Redis backend: uses distributed SETNX lock (protects across workers)

    Usage:
        async with authorization_lock(username, filter):
            # Only one request at a time (per worker or globally) reaches here
            result = await check_ldap(...)
    """
    key = _make_cache_key(username, authorization_filter)

    if _USE_REDIS_BACKEND:
        async with _redis_lock(key):
            yield
    else:
        async with await _get_memory_lock(key):
            yield


async def get_cached_authorization(
    username: str, authorization_filter: str | None
) -> bool | None:
    """
    Get cached authorization result.

    Returns True/False if cached, None if not in cache.
    """
    key = _make_cache_key(username, authorization_filter)

    if _USE_REDIS_BACKEND:
        return await _redis_get(key)
    return _memory_get(key)


async def set_cached_authorization(
    username: str,
    authorization_filter: str | None,
    *,
    authorized: bool,
) -> None:
    """Cache an authorization result."""
    if settings.header_auth_cache_ttl <= 0:
        return  # Caching disabled

    key = _make_cache_key(username, authorization_filter)

    if _USE_REDIS_BACKEND:
        await _redis_set(key, authorized, settings.header_auth_cache_ttl)
    else:
        _memory_set(key, authorized, settings.header_auth_cache_ttl)


# --- In-memory implementation ---


async def _get_memory_lock(key: str) -> asyncio.Lock:
    """
    Get or create a lock for a specific cache key.

    Implements LRU-based cleanup: when the number of locks exceeds _MAX_LOCKS,
    the oldest unused locks are pruned to prevent unbounded memory growth.
    """
    async with _key_locks_lock:
        current_time = time.time()

        if key in _key_locks:
            # Update access time and return existing lock
            lock, _ = _key_locks[key]
            _key_locks[key] = (lock, current_time)
            return lock

        # Create new lock
        lock = asyncio.Lock()
        _key_locks[key] = (lock, current_time)

        # Prune oldest locks if we exceed the limit
        if len(_key_locks) > _MAX_LOCKS:
            _prune_oldest_locks()

        return lock


def _prune_oldest_locks() -> None:
    """
    Remove the oldest 10% of locks based on last access time.

    This is called under _key_locks_lock, so no additional locking needed.
    Only prunes locks that are not currently held (locked).
    """
    # Calculate how many to remove (10% of max, minimum 1)
    num_to_remove = max(1, _MAX_LOCKS // 10)

    # Sort by last access time (oldest first), filter out currently held locks
    candidates = [
        (k, access_time)
        for k, (lock, access_time) in _key_locks.items()
        if not lock.locked()
    ]
    candidates.sort(key=lambda x: x[1])

    # Remove oldest candidates
    removed = 0
    for key, _ in candidates:
        if removed >= num_to_remove:
            break
        if key in _key_locks and not _key_locks[key][0].locked():
            # Re-check lock state in case it was acquired after the snapshot.
            del _key_locks[key]
            removed += 1

    if removed > 0:
        logger.debug("cache.locks.pruned", count=removed, remaining=len(_key_locks))


def _memory_get(key: str) -> bool | None:
    entry = _cache.get(key)
    if entry is None:
        logger.debug("cache.miss", key=key, backend="memory")
        return None

    authorized, expires_at = entry
    if time.time() > expires_at:
        del _cache[key]
        logger.debug("cache.expired", key=key, backend="memory")
        return None

    logger.debug("cache.hit", key=key, authorized=authorized, backend="memory")
    return authorized


def _memory_set(key: str, authorized: bool, ttl: int) -> None:  # noqa: FBT001
    _cache[key] = (authorized, time.time() + ttl)
    logger.debug("cache.set", key=key, authorized=authorized, ttl=ttl, backend="memory")


# --- Redis implementation ---


async def _redis_get(key: str) -> bool | None:
    """
    Get cached authorization result from Redis.

    :param key: Cache key to retrieve.
    :returns: Cached authorization result or ``None``.
    """
    redis = _get_redis_connection()
    if redis is None:
        logger.error("cache.redis.unavailable", action="get", key=key)
        return _memory_get(key)

    full_key = f"{settings.redis_prefix}{key}"
    value = await redis.get(full_key)

    if value is None:
        logger.debug("cache.miss", key=full_key, backend="redis")
        return None

    authorized = value in {b"1", "1"}
    logger.debug("cache.hit", key=full_key, authorized=authorized, backend="redis")
    return authorized


async def _redis_set(key: str, authorized: bool, ttl: int) -> None:  # noqa: FBT001
    """
    Set cached authorization result in Redis.

    :param key: Cache key to set.
    :param authorized: Authorization result to cache.
    :param ttl: Cache time-to-live in seconds.
    """
    redis = _get_redis_connection()
    if redis is None:
        logger.error("cache.redis.unavailable", action="set", key=key)
        _memory_set(key, authorized, ttl)
        return

    full_key = f"{settings.redis_prefix}{key}"
    value = "1" if authorized else "0"
    await redis.setex(full_key, ttl, value)
    logger.debug(
        "cache.set", key=full_key, authorized=authorized, ttl=ttl, backend="redis"
    )


@asynccontextmanager
async def _redis_lock(key: str) -> AsyncGenerator[None, None]:
    """
    Distributed lock using Redis SETNX pattern.

    Acquires a lock that works across all workers/processes.
    If lock cannot be acquired, waits and retries with exponential backoff.

    :param key: Cache key to lock.
    """
    redis = _get_redis_connection()
    if redis is None:
        logger.error("cache.redis.unavailable", action="lock", key=key)
        # Fallback to memory lock if Redis unavailable
        async with await _get_memory_lock(key):
            yield
        return

    lock_key = f"{settings.redis_prefix}lock:{key}"
    acquired = False
    retry_delay = 0.01  # Start with 10ms
    max_delay = 0.5  # Max 500ms between retries
    max_wait = _REDIS_LOCK_TTL  # Don't wait longer than lock TTL

    start_time = time.time()

    try:
        while not acquired:
            # Try to acquire lock with NX (only set if not exists) and EX (expiry)
            acquired = await redis.set(lock_key, "1", nx=True, ex=_REDIS_LOCK_TTL)

            if acquired:
                logger.debug("cache.lock.acquired", key=lock_key)
                break

            # Check if we've waited too long
            if time.time() - start_time > max_wait:
                # Give up waiting and proceed without lock
                #
                # Trade-off: Availability over consistency
                # - PRO: Prevents indefinite blocking during Redis issues
                # - PRO: Service stays available under high contention
                # - CON: May cause duplicate LDAP queries (thundering herd)
                # - SAFETY: Fail-safe - more restrictive auth result wins
                #   via cache expiration
                logger.warning("cache.lock.timeout", key=lock_key)
                break

            # Wait with exponential backoff
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, max_delay)

        yield

    finally:
        if acquired:
            await redis.delete(lock_key)
            logger.debug("cache.lock.released", key=lock_key)


# --- Test helpers ---


def reset_cache() -> None:
    """Reset cache state (for testing)."""
    global _cache, _key_locks  # noqa: PLW0603
    _cache = {}
    _key_locks = {}


def get_lock_count() -> int:
    """Return the current number of locks (for monitoring/testing)."""
    return len(_key_locks)
