import re
import time
from functools import wraps
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from flask import session, redirect, url_for, flash, abort, g

from db import get_db

_ph = PasswordHasher()

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')
# 8~64자, 영문/숫자/특수문자 각 1개 이상 포함
PASSWORD_RE = re.compile(
    r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?~`]).{8,64}$'
)

LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 5 * 60


def hash_password(raw_password: str) -> str:
    return _ph.hash(raw_password)


def verify_password(password_hash: str, raw_password: str) -> bool:
    try:
        return _ph.verify(password_hash, raw_password)
    except (VerifyMismatchError, InvalidHash):
        return False


def validate_username(username: str) -> bool:
    return bool(username) and bool(USERNAME_RE.match(username))


def validate_password(password: str) -> bool:
    return bool(password) and bool(PASSWORD_RE.match(password))


def validate_price(price_str: str):
    """가격 문자열을 검증하고, 유효하면 int를, 아니면 None을 반환"""
    if not price_str or not price_str.isdigit():
        return None
    price = int(price_str)
    if price < 0 or price > 10_000_000_000:
        return None
    return price


def validate_amount(amount_str: str):
    return validate_price(amount_str)


def clean_text(text: str, max_len: int) -> str:
    """제어 문자를 제거하고 길이를 제한한다. HTML 이스케이프는 Jinja autoescape가 담당."""
    if text is None:
        return ''
    text = ''.join(ch for ch in text if ch == '\n' or ch == '\t' or ord(ch) >= 32)
    return text.strip()[:max_len]


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        db = get_db()
        user = db.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],)).fetchone()
        if user is None or user['is_banned']:
            session.clear()
            flash('계정을 이용할 수 없습니다. (탈퇴 또는 휴면 처리됨)')
            return redirect(url_for('login'))
        g.current_user = user
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        db = get_db()
        user = db.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],)).fetchone()
        if user is None or user['is_banned']:
            session.clear()
            return redirect(url_for('login'))
        if not user['is_admin']:
            abort(403)
        g.current_user = user
        return view(*args, **kwargs)
    return wrapped


class RateLimiter:
    """단일 프로세스 기준 간이 슬라이딩 윈도우 rate limiter (다중 프로세스 배포 시 Redis 등으로 교체 필요)"""

    def __init__(self):
        self._hits = defaultdict(deque)

    def allow(self, key: str, max_hits: int, window_seconds: float) -> bool:
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()
        if len(bucket) >= max_hits:
            return False
        bucket.append(now)
        return True


chat_rate_limiter = RateLimiter()
report_rate_limiter = RateLimiter()
