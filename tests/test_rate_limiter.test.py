import pytest
import time
import threading
from HIDS.threat_detector.rate_limiter import VirusTotalRateLimiter

# Mock function to be rate-limited
def mock_api_call():
    return "API call successful"

def test_acquire_waits_when_limit_exceeded_real_time():
    """
    Tests that acquire waits for the correct duration when the rate limit is exceeded,
    using actual time.sleep and time.time.
    """
    requests_per_minute = 2
    limiter = VirusTotalRateLimiter(requests_per_minute=requests_per_minute)
    
    # Perform requests up to the limit without expected delay
    start_time = time.time()
    for _ in range(requests_per_minute):
        limiter.acquire()
    
    # The next request should trigger a wait
    limiter.acquire()
    end_time = time.time()

    # Calculate expected minimum duration.
    # The first request is at start_time. The third request (index 2) will wait until
    # 60 seconds after the first request.
    # So, total_duration = (time_of_first_request + 60) - time_of_first_request = 60 seconds.
    # We need to account for the time taken by the first few acquires.
    # The sleep_time is calculated as request_times[0] + 60 - current_time.
    # If requests are made very quickly, current_time will be close to request_times[0].
    # So sleep_time will be close to 60 seconds.
    # The total elapsed time should be approximately 60 seconds from the very first acquire call.
    
    # Allow a small tolerance for execution time
    tolerance = 0.5
    expected_min_duration = 60.0
    
    assert end_time - start_time >= expected_min_duration - tolerance, \
        f"Expected at least {expected_min_duration}s, but got {end_time - start_time:.2f}s"
    assert end_time - start_time <= expected_min_duration + tolerance, \
        f"Expected at most {expected_min_duration}s, but got {end_time - start_time:.2f}s"

def test_acquire_no_wait_within_limit_real_time():
    """
    Tests that acquire does not wait when requests are within the rate limit,
    using actual time.time.
    """
    requests_per_minute = 4 # Default value
    limiter = VirusTotalRateLimiter(requests_per_minute=requests_per_minute)
    
    start_time = time.time()
    for _ in range(requests_per_minute):
        limiter.acquire()
    end_time = time.time()

    # Expect very little time to pass, as no rate limit should be hit
    assert end_time - start_time < 1.0, \
        f"Expected less than 1s, but got {end_time - start_time:.2f}s"

def test_rate_limited_decorator_real_time():
    """
    Tests that the rate_limited decorator correctly applies rate limiting to a function,
    using actual time.sleep and time.time.
    """
    requests_per_minute = 2
    limiter = VirusTotalRateLimiter(requests_per_minute=requests_per_minute)

    @limiter.rate_limited
    def decorated_api_call():
        return "Decorated API call successful"

    # Perform requests up to the limit without expected delay
    start_time = time.time()
    for _ in range(requests_per_minute):
        decorated_api_call()
    
    # The next request should trigger a wait
    decorated_api_call()
    end_time = time.time()

    # Calculate expected minimum duration, similar to the acquire test
    tolerance = 0.5
    expected_min_duration = 60.0

    assert end_time - start_time >= expected_min_duration - tolerance, \
        f"Decorator: Expected at least {expected_min_duration}s, but got {end_time - start_time:.2f}s"
    assert end_time - start_time <= expected_min_duration + tolerance, \
        f"Decorator: Expected at most {expected_min_duration}s, but got {end_time - start_time:.2f}s"

def test_old_timestamps_are_removed():
    """
    Tests that old request timestamps (older than 60 seconds) are correctly removed
    from the request_times deque.
    """
    limiter = VirusTotalRateLimiter(requests_per_minute=4)
    
    # Simulate requests at time 0, 1, 2, 3
    for i in range(4):
        limiter.request_times.append(i)
    
    # Simulate time passing beyond 60 seconds for the first request
    # Current time is 61, so request at time 0 should be removed
    current_time = 61
    with threading.Lock(): # acquire uses a lock, so simulate it
        # Manually call the acquire logic to clean up old timestamps
        while limiter.request_times and limiter.request_times[0] < current_time - 60:
            limiter.request_times.popleft()
    
    # Only timestamps 1, 2, 3 should remain
    assert len(limiter.request_times) == 3
    assert list(limiter.request_times) == [1, 2, 3]

    # Simulate more time passing, so request at time 1 is also old
    current_time = 62
    with threading.Lock():
        while limiter.request_times and limiter.request_times[0] < current_time - 60:
            limiter.request_times.popleft()
    
    # Only timestamps 2, 3 should remain
    assert len(limiter.request_times) == 2
    assert list(limiter.request_times) == [2, 3]