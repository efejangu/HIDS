import logging
import os
from datetime import datetime
from pydantic import BaseModel
from queue import Queue

alert_queue = Queue()

log_dir = "app_log"

if not os.path.exists(log_dir):
    os.makedirs(log_dir)

#
ALERT_I = 51
ALERT_II = 52
ALERT_III = 53

logging.addLevelName(ALERT_I, "ALERT I")
logging.addLevelName(ALERT_II, "ALERT II")
logging.addLevelName(ALERT_III, "ALERT III")

# Configured logger
logging.basicConfig(
    filename=os.path.join(log_dir, "alert.log"),
    level=ALERT_I,  # Set to the lowest custom alert level to capture all alerts
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Configured logger instance
logger = logging.getLogger(__name__)

class Alert(BaseModel):
    timestamp: datetime
    alertLevel: str
    message: str
    detected_by: str



