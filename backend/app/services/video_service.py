import os
import cv2
import threading
import time
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.camera import Camera
from app.schemas.alerts import AlertCreate
from app.services.alert_service import alert_service
from app.core.database import SessionLocal

logger = logging.getLogger("video")

# Lazy import for ultralytics to allow the service to start up or be tested even if imports fail
if os.environ.get("TESTING") == "1":
    YOLO = None
else:
    try:
        from ultralytics import YOLO
    except (ImportError, Exception):
        YOLO = None


class VideoService:
    def __init__(self):
        self.active_threads: Dict[int, threading.Thread] = {}
        self.active_streams: Dict[int, cv2.VideoCapture] = {}
        self.running_flags: Dict[int, bool] = {}
        
        # Latest frame buffer for MJPEG streaming: camera_id -> jpeg_bytes
        self.latest_frames: Dict[int, bytes] = {}
        
        # Metrics storage: camera_id -> dict
        self.camera_fps: Dict[int, float] = {}
        self.processed_frames: Dict[int, int] = {}
        self.start_times: Dict[int, float] = {}
        
        # Model path configuration
        self.model_path = settings.MODEL_PATH
        self._model = None
        
        # Verify model file presence on initialization
        if not os.path.exists(self.model_path):
            logger.error(f"Trained YOLO PPE model not found at path: {self.model_path}")
            # We do not raise error immediately in __init__ to allow backend tests and startup 
            # to run without the file if the video service is not actively used.
            # However, we will raise an error when model loading is attempted.
        else:
            logger.info(f"Verified YOLO PPE model exists at {self.model_path}")

    def get_model(self):
        """Loads and returns the YOLO model, raising a configuration error if missing."""
        if self._model is not None:
            return self._model
            
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"YOLO PPE model file is missing at configured path: {self.model_path}. "
                "Please place the trained 'best.pt' file in that location."
            )
            
        if YOLO is None:
            raise ImportError(
                "The 'ultralytics' library is not installed. Please check backend requirements."
            )
            
        logger.info(f"Loading YOLO PPE model from {self.model_path}...")
        try:
            self._model = YOLO(self.model_path)
            logger.info("YOLO PPE model loaded successfully.")
            return self._model
        except Exception as e:
            logger.error(f"Error loading YOLO model: {str(e)}")
            raise ValueError(f"Failed to load YOLO model: {str(e)}")

    def get_status(self, camera_id: int) -> dict:
        """Get ingestion status, FPS, and processed frames count for a camera."""
        is_running = self.running_flags.get(camera_id, False)
        fps = self.camera_fps.get(camera_id, 0.0)
        frames = self.processed_frames.get(camera_id, 0)
        uptime = 0.0
        if is_running and camera_id in self.start_times:
            uptime = time.time() - self.start_times[camera_id]
            
        return {
            "is_running": is_running,
            "fps": round(fps, 1),
            "processed_frames": frames,
            "uptime_seconds": round(uptime, 1)
        }

    def start_camera(self, camera_id: int, db: Session) -> bool:
        """Starts background frame capture and YOLO inference thread for a camera."""
        if self.running_flags.get(camera_id, False):
            logger.warning(f"Camera {camera_id} is already running.")
            return True
            
        camera = db.query(Camera).filter(Camera.id == camera_id).first()
        if not camera:
            logger.error(f"Camera {camera_id} not found in database.")
            return False
            
        # Ensure model is loadable before starting stream (will raise FileNotFoundError if missing)
        try:
            self.get_model()
        except Exception as e:
            logger.error(f"Cannot start camera {camera_id}: {str(e)}")
            raise e

        # Set stream source: can be an integer (webcam index) or string (video file path/RTSP)
        source = camera.stream_url
        if source is None:
            source = 0  # Default to local webcam
        else:
            # Try to convert to integer if it's a numeric string
            try:
                source = int(source)
            except ValueError:
                pass
                
        # Set running flags and start background thread
        self.running_flags[camera_id] = True
        self.processed_frames[camera_id] = 0
        self.camera_fps[camera_id] = 0.0
        self.start_times[camera_id] = time.time()
        
        thread = threading.Thread(
            target=self._ingestion_loop,
            args=(camera_id, source),
            daemon=True
        )
        self.active_threads[camera_id] = thread
        thread.start()
        
        # Update camera status in database
        camera.status = "online"
        camera.is_ingesting = True
        camera.last_active = datetime.now(timezone.utc)
        db.add(camera)
        db.commit()
        
        logger.info(f"Started ingestion thread for Camera {camera_id} (Source: {source})")
        return True

    def stop_camera(self, camera_id: int, db: Session) -> bool:
        """Stops the ingestion stream and thread for a camera."""
        if not self.running_flags.get(camera_id, False):
            logger.warning(f"Camera {camera_id} is not running.")
            return True
            
        self.running_flags[camera_id] = False
        
        # Join thread
        thread = self.active_threads.get(camera_id)
        if thread and thread.is_alive():
            thread.join(timeout=2.0)
            
        # Clean up lists
        self.active_threads.pop(camera_id, None)
        self.active_streams.pop(camera_id, None)
        self.latest_frames.pop(camera_id, None)
        self.camera_fps.pop(camera_id, None)
        self.start_times.pop(camera_id, None)
        
        # Update camera status in DB
        camera = db.query(Camera).filter(Camera.id == camera_id).first()
        if camera:
            camera.status = "offline"
            camera.is_ingesting = False
            camera.last_active = datetime.now(timezone.utc)
            db.add(camera)
            db.commit()
            
        logger.info(f"Stopped ingestion thread for Camera {camera_id}")
        return True

    def _ingestion_loop(self, camera_id: int, source):
        """Thread worker loop that captures frames, performs YOLO inference, and draws alerts."""
        cap = cv2.VideoCapture(source)
        if not cap.isOpened():
            logger.error(f"Failed to open video source '{source}' for Camera {camera_id}")
            self.running_flags[camera_id] = False
            
            # Update database status to error/offline
            db = SessionLocal()
            camera = db.query(Camera).filter(Camera.id == camera_id).first()
            if camera:
                camera.status = "offline"
                camera.is_ingesting = False
                db.add(camera)
                db.commit()
            db.close()
            return

        self.active_streams[camera_id] = cap
        model = self.get_model()
        
        frame_count = 0
        start_time = time.time()
        
        # Create a simple placeholder frame in case we need it
        _, placeholder_img = cv2.imencode('.jpg', cv2.imread('app/static/placeholder.jpg') if os.path.exists('app/static/placeholder.jpg') else bytes())
        
        while self.running_flags.get(camera_id, False):
            ret, frame = cap.read()
            if not ret:
                # If it's a video file, loop back to the beginning
                if isinstance(source, str) and source.endswith(('.mp4', '.avi', '.mov', '.mkv')):
                    cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                    continue
                else:
                    logger.warning(f"Empty frame or stream ended for Camera {camera_id}")
                    time.sleep(0.5)
                    continue

            # Run YOLO model inference
            # We resize for speed and consistency
            resized_frame = cv2.resize(frame, (640, 480))
            
            try:
                results = model(resized_frame, verbose=False)
                
                # Check for PPE violations based on classes detected
                # Standard yolov8 detections will yield classes like 'person', 'helmet', 'vest', 'no-helmet', 'no-vest'
                self._check_for_violations(camera_id, results)
                
                # Render/plot bounding boxes on the frame
                annotated_frame = results[0].plot()
            except Exception as e:
                logger.error(f"Error during YOLO inference: {str(e)}")
                annotated_frame = resized_frame

            # Encode annotated frame as JPEG
            ret_enc, jpeg_buf = cv2.imencode('.jpg', annotated_frame)
            if ret_enc:
                self.latest_frames[camera_id] = jpeg_buf.tobytes()

            # Track FPS and metrics
            frame_count += 1
            self.processed_frames[camera_id] = frame_count
            
            elapsed = time.time() - start_time
            if elapsed >= 1.0:
                self.camera_fps[camera_id] = frame_count / elapsed
                # Reset tracking
                frame_count = 0
                start_time = time.time()

            # Throttle loop to target FPS (e.g., 10-15 FPS is plenty for safety surveillance)
            time.sleep(1.0 / 15.0)

        # Release stream
        cap.release()
        logger.info(f"Released Capture resource for Camera {camera_id}")

    def _check_for_violations(self, camera_id: int, results):
        """Analyzes bounding boxes and classes to trigger safety alerts in DB."""
        if not results or len(results) == 0:
            return
            
        boxes = results[0].boxes
        names = results[0].names
        
        # Compile counts of detected objects
        person_count = 0
        helmet_count = 0
        vest_count = 0
        no_helmet_detected = False
        no_vest_detected = False
        
        for box in boxes:
            cls_idx = int(box.cls[0].item())
            name = names.get(cls_idx, "").lower()
            conf = float(box.conf[0].item())
            
            if conf < 0.4:
                continue  # skip low confidence detections
                
            if "person" in name:
                person_count += 1
            elif "helmet" in name or "hard" in name or "hat" in name:
                # If the class name explicitly contains "no-helmet" or "no helmet"
                if "no" in name:
                    no_helmet_detected = True
                else:
                    helmet_count += 1
            elif "vest" in name or "jacket" in name:
                if "no" in name:
                    no_vest_detected = True
                else:
                    vest_count += 1
                    
        # Decision logic:
        # 1. Direct violation classes found
        # 2. Logic deduction: If persons detected > helmets/vests detected (and no explicit violation classes)
        db = SessionLocal()
        try:
            if no_helmet_detected or (person_count > 0 and helmet_count < person_count):
                self._trigger_safety_alert(
                    db,
                    camera_id=camera_id,
                    violation_type="no-helmet",
                    title="PPE Violation: Missing Safety Helmet",
                    description=f"Safety inspection detected worker(s) inside Vault perimeter without protective helmet gear. Counts: Persons={person_count}, Helmets={helmet_count}."
                )
                
            if no_vest_detected or (person_count > 0 and vest_count < person_count):
                self._trigger_safety_alert(
                    db,
                    camera_id=camera_id,
                    violation_type="no-vest",
                    title="PPE Violation: Missing High-Vis Vest",
                    description=f"Safety inspection detected worker(s) inside Vault perimeter without high-visibility safety vest. Counts: Persons={person_count}, Vests={vest_count}."
                )
        except Exception as e:
            logger.error(f"Failed to check/trigger safety alert: {str(e)}")
        finally:
            db.close()

    def _trigger_safety_alert(self, db: Session, camera_id: int, violation_type: str, title: str, description: str):
        """Builds AlertCreate schema and posts to alert_service."""
        # Check cooldown before creating DB entry and loading camera objects
        if alert_service.is_in_cooldown(camera_id, violation_type):
            return

        alert_data = AlertCreate(
            camera_id=camera_id,
            title=title,
            violation_type=violation_type,
            severity="high",
            status="active",
            description=description,
            evidence_path=f"/uploads/alerts/cam_{camera_id}_{violation_type}.jpg"
        )
        alert_service.create_alert(db, alert_data)


video_service = VideoService()
