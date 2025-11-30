import time
import threading
from collections import deque
from functools import wraps
import logging

class VirusTotalRateLimiter:
    """
    Rate limiter for VirusTotal API calls.
    Implements token bucket algorithm with queueing for the api.
    """
    
    def __init__(self, requests_per_minute=4):
        self.requests_per_minute = requests_per_minute
        self.min_interval = 60.0 / requests_per_minute  # Time between requests
        self.request_times = deque()
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        
    def acquire(self):
        """Acquire a token for making an API request, waiting if necessary."""
        with self.lock:
            current_time = time.time()
            
            # Remove timestamps older than 60 seconds
            while self.request_times and self.request_times[0] < current_time - 60:
                self.request_times.popleft()
            
            # When over 4 timestamps are in the deque we hit a limit
            if len(self.request_times) >= self.requests_per_minute:
                sleep_time = self.request_times[0] + 60 - current_time 
                if sleep_time > 0:
                    self.logger.info(f"Rate limit reached. Waiting {sleep_time:.2f} seconds...")
                    time.sleep(sleep_time)
                    current_time = time.time()
                    # Clean up old entries after waiting
                    while self.request_times and self.request_times[0] < current_time - 60:
                        self.request_times.popleft()
            
            # Add current request timestamp
            self.request_times.append(current_time)
    
    def rate_limited(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            self.acquire()
            return func(*args, **kwargs)
        return wrapper

# Global rate limiter instance
vt_rate_limiter = VirusTotalRateLimiter(requests_per_minute=4)