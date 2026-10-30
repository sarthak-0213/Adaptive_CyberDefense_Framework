import asyncio
import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from app.core.config import settings
from app.schemas.mtd import PathRotationInfo, HoneypotLogEntry, MTDStatusResponse

logger = logging.getLogger("mtd")


class MTDService:
    def __init__(self):
        self.enabled: bool = settings.MTD_ENABLED
        self.rotation_interval: int = settings.MTD_ROTATION_INTERVAL_SECONDS
        self.decoy_paths: Set[str] = set(settings.MTD_DECOY_PATHS)
        self.seed: str = settings.MTD_SEED
        
        # Registry store
        self.active_routes: Dict[str, str] = {}  # dynamic_path -> real_path
        self.reverse_active_routes: Dict[str, str] = {}  # real_path -> dynamic_path
        self.history: List[PathRotationInfo] = []
        self.last_rotation: Optional[datetime] = None
        self.honeypot_logs: List[HoneypotLogEntry] = []
        
        # Background task handle
        self._scheduler_task: Optional[asyncio.Task] = None
        
        # List of internal paths to protect/rotate
        self.protected_paths = [
            "/api/v1/auth/me",
            "/api/v1/auth/logout",
            "/gateway/api/admin/dashboard",
            "/gateway/secureshop/api/admin/dashboard",
        ]
        
        # Load config and restore logs from database
        self.load_config()

    def load_config(self) -> None:
        """Loads and syncs config with settings dynamic updates."""
        self.enabled = settings.MTD_ENABLED
        self.rotation_interval = settings.MTD_ROTATION_INTERVAL_SECONDS
        self.decoy_paths = set(settings.MTD_DECOY_PATHS)
        self.seed = settings.MTD_SEED
        logger.info("MTD settings loaded / refreshed.")
        
        # Sync honeypot logs from database if database is configured/accessible
        try:
            from app.core.database import SessionLocal
            from app.models.honeypot import HoneypotLog
            db = SessionLocal()
            try:
                db_logs = db.query(HoneypotLog).order_by(HoneypotLog.timestamp.asc()).all()
                self.honeypot_logs = [
                    HoneypotLogEntry(
                        id=log.id,
                        decoy_path_triggered=log.decoy_path_triggered,
                        ip_address=log.ip_address,
                        user_agent=log.user_agent,
                        timestamp=log.timestamp,
                        headers_logged=log.headers_logged or {}
                    ) for log in db_logs
                ]
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"Could not load honeypot logs from database: {str(e)}")

    def generate_dynamic_path(self, real_path: str, salt: str) -> str:
        """Generates a pseudo-random path for a real endpoint based on path, seed, and salt."""
        hash_input = f"{real_path}-{self.seed}-{salt}".encode("utf-8")
        path_hash = hashlib.sha256(hash_input).hexdigest()[:8]
        # Return a dynamic path format, e.g., /api/v1/d/a8b9c1e2
        return f"/api/v1/d/{path_hash}"

    def rotate_paths(self) -> None:
        """Rotates active paths by generating new dynamic aliases."""
        if not self.enabled:
            logger.info("MTD is disabled. Skipping path rotation.")
            return

        from app.core.redis import redis_client
        r = redis_client.get_client()
        lock = None
        if r:
            lock = r.lock("mtd:rotation_lock", timeout=10)
            if not lock.acquire(blocking=False):
                logger.info("Another worker is currently rotating MTD paths, skipping.")
                return

        try:
            self.load_config()
            salt = secrets.token_hex(8)
            new_active_routes = {}
            new_reverse_active_routes = {}
            now = datetime.now(timezone.utc)

            # Deprecate old routes in history
            for dyn_path, real_path in self.active_routes.items():
                # Check if already in history
                exists = any(h.dynamic_path == dyn_path and h.status == "active" for h in self.history)
                if exists:
                    for h in self.history:
                        if h.dynamic_path == dyn_path:
                            h.status = "deprecated"

            # Generate new routes
            for real_path in self.protected_paths:
                dyn_path = self.generate_dynamic_path(real_path, salt)
                new_active_routes[dyn_path] = real_path
                new_reverse_active_routes[real_path] = dyn_path
                
                # Record rotation in history
                rotation_info = PathRotationInfo(
                    dynamic_path=dyn_path,
                    target_handler=real_path,
                    created_at=now,
                    status="active"
                )
                self.history.append(rotation_info)

            # Maintain history limit
            if len(self.history) > settings.MTD_ROTATION_HISTORY_LIMIT:
                self.history = self.history[-settings.MTD_ROTATION_HISTORY_LIMIT:]

            self.active_routes = new_active_routes
            self.reverse_active_routes = new_reverse_active_routes
            self.last_rotation = now
            
            from app.core.redis import redis_client
            r = redis_client.get_client()
            if r:
                if r.exists("mtd:active_routes"):
                    r.delete("mtd:active_routes")
                if r.exists("mtd:reverse_routes"):
                    r.delete("mtd:reverse_routes")
                    
                if new_active_routes:
                    r.hset("mtd:active_routes", mapping=new_active_routes)
                    r.hset("mtd:reverse_routes", mapping=new_reverse_active_routes)
                    
                # Add deprecated routes to set
                for dyn_path in new_active_routes:
                    r.sadd("mtd:deprecated_routes", dyn_path)

            logger.info(f"MTD Path Rotation executed. Active dynamic routes: {self.get_active_routes()}")
        finally:
            if lock and lock.owned():
                lock.release()

    def get_active_routes(self) -> Dict[str, str]:
        from app.core.redis import redis_client
        r = redis_client.get_client()
        if r:
            return r.hgetall("mtd:active_routes") or self.active_routes
        return self.active_routes

    def is_deprecated_route(self, path: str) -> bool:
        from app.core.redis import redis_client
        r = redis_client.get_client()
        if r:
            return r.sismember("mtd:deprecated_routes", path)
        return any(h.dynamic_path == path and h.status == "deprecated" for h in self.history)

    async def start_rotation_scheduler(self) -> None:
        """Starts the background task to periodically rotate paths."""
        if self._scheduler_task is not None:
            logger.warning("MTD rotation scheduler already running.")
            return

        # Perform initial rotation
        self.rotate_paths()

        async def scheduler_loop():
            try:
                while True:
                    await asyncio.sleep(self.rotation_interval)
                    self.rotate_paths()
            except asyncio.CancelledError:
                logger.info("MTD rotation scheduler task cancelled.")
            except Exception as e:
                logger.error(f"MTD rotation scheduler error: {str(e)}")

        self._scheduler_task = asyncio.create_task(scheduler_loop())
        logger.info("MTD path rotation scheduler background task spawned.")

    async def stop_rotation_scheduler(self) -> None:
        """Stops the background scheduler task."""
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
            self._scheduler_task = None
            logger.info("MTD path rotation scheduler stopped.")

    def log_honeypot_trigger(self, path: str, ip_address: str, user_agent: Optional[str], headers: Dict[str, str]) -> HoneypotLogEntry:
        """Logs a honeypot trigger event and generates telemetry logs."""
        # Sanitize/filter headers for security/privacy (optional)
        sanitized_headers = {k: v for k, v in headers.items() if k.lower() not in ["authorization", "cookie"]}
        
        # Save to database
        try:
            from app.core.database import SessionLocal
            from app.models.honeypot import HoneypotLog
            db = SessionLocal()
            try:
                db_log = HoneypotLog(
                    decoy_path_triggered=path,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    timestamp=datetime.now(timezone.utc),
                    headers_logged=sanitized_headers
                )
                db.add(db_log)
                db.commit()
                db.refresh(db_log)
                log_id = db_log.id
                timestamp = db_log.timestamp
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to log honeypot trigger to database: {str(e)}")
            log_id = len(self.honeypot_logs) + 1
            timestamp = datetime.now(timezone.utc)

        entry = HoneypotLogEntry(
            id=log_id,
            decoy_path_triggered=path,
            ip_address=ip_address,
            user_agent=user_agent,
            timestamp=timestamp,
            headers_logged=sanitized_headers
        )
        self.honeypot_logs.append(entry)
        logger.warning(
            f"SECURITY ALERT - HONEYPOT TRIGGERED: Decoy Path={path}, IP={ip_address}, UA={user_agent}"
        )
        
        # Record event in threat mitigation engine AND risk engine
        try:
            from app.core.database import SessionLocal
            from app.services.threat_mitigation import threat_mitigation_service
            from app.services.threat_correlation import threat_correlation
            db = SessionLocal()
            try:
                threat_mitigation_service.record_event(
                    db=db,
                    ip_address=ip_address,
                    reason=f"Honeypot trigger on decoy path: {path}"
                )
                threat_correlation.on_honeypot_hit(db=db, ip_address=ip_address, path=path)
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to record threat mitigation event: {str(e)}")

        return entry

    def get_status(self) -> MTDStatusResponse:
        """Returns the current MTD registry status, metrics, and active path registry mapping."""
        now = datetime.now(timezone.utc)
        next_rotation_in = 0.0
        if self.last_rotation and self.enabled:
            elapsed = (now - self.last_rotation).total_seconds()
            next_rotation_in = max(0.0, self.rotation_interval - elapsed)

        return MTDStatusResponse(
            mtd_enabled=self.enabled,
            current_seed=self.seed,
            active_routes=self.active_routes,
            decoy_paths=list(self.decoy_paths),
            rotation_interval_seconds=self.rotation_interval,
            last_rotation=self.last_rotation,
            next_rotation_in_seconds=next_rotation_in if self.enabled else None,
            rotation_history=self.history
        )


# Singleton MTD service instance
mtd_service = MTDService()
