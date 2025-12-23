import os, json
from datetime import datetime, timedelta
from flask import jsonify, session
from functools import wraps

# -------- Paths (import-safe) --------
BASE = os.path.dirname(os.path.abspath(__file__))
IDEAS = os.path.join(BASE, 'ideas')

ANALYTICS = os.path.join(BASE, 'analytics')
LOGIN_LOG = os.path.join(ANALYTICS, 'logins.json')

os.makedirs(ANALYTICS, exist_ok=True)


# -------- Helpers --------
def log_login_event(username, role):
    entry = {
        "username": username,
        "role": role,
        "time": datetime.now().isoformat()
    }

    logs = []

    if os.path.exists(LOGIN_LOG):
        try:
            with open(LOGIN_LOG, 'r') as f:
                content = f.read().strip()
                if content:
                    logs = json.loads(content)
        except Exception:
            logs = []

    logs.append(entry)

    with open(LOGIN_LOG, 'w') as f:
        json.dump(logs, f, indent=2)


def count_total_ideas():
    total = 0
    if not os.path.exists(IDEAS):
        return 0

    for user_folder in os.listdir(IDEAS):
        user_path = os.path.join(IDEAS, user_folder)
        if os.path.isdir(user_path):
            total += len([
                d for d in os.listdir(user_path)
                if os.path.isdir(os.path.join(user_path, d))
            ])
    return total


def get_active_user_count(window_minutes=5):
    active_file = os.path.join(ANALYTICS, 'active.json')
    if not os.path.exists(active_file):
        return 0

    try:
        with open(active_file, 'r') as f:
            active = json.load(f)
    except Exception:
        return 0

    now = datetime.now()
    count = 0

    for last_seen in active.values():
        try:
            t = datetime.fromisoformat(last_seen)
            if (now - t).total_seconds() < window_minutes * 60:
                count += 1
        except Exception:
            pass

    return count


def get_login_logs():
    if not os.path.exists(LOGIN_LOG):
        return []
    with open(LOGIN_LOG, 'r') as f:
        return json.load(f)
