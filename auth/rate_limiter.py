from datetime import datetime, timedelta
from collections import defaultdict

login_attempts = defaultdict(list)
blocked_ips = {}

MAX_ATTEMPTS = 5
BLOCK_DURATION_MINUTES = 15

def record_attempt(ip):
    now = datetime.utcnow()
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < timedelta(minutes=10)]
    login_attempts[ip].append(now)
    if len(login_attempts[ip]) >= MAX_ATTEMPTS:
        blocked_ips[ip] = now + timedelta(minutes=BLOCK_DURATION_MINUTES)
        return False
    return True

def is_blocked(ip):
    if ip in blocked_ips:
        if datetime.utcnow() < blocked_ips[ip]:
            return True
        else:
            del blocked_ips[ip]
    return False
