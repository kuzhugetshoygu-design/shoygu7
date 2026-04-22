import hashlib
import base64
import time
from functools import wraps

def compute_sha256(file_path):
    """Вычисляет SHA-256 хеш файла"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def base64_url_encode(data):
    """Base64 URL-safe кодирование"""
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

def rate_limit(requests_per_minute=4):
    """Декоратор для ограничения частоты запросов"""
    min_interval = 60.0 / requests_per_minute
    last_called = [0.0]

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            elapsed = time.time() - last_called[0]
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
            last_called[0] = time.time()
            return func(*args, **kwargs)
        return wrapper
    return decorator

def parse_stats(stats):
    """Парсит статистику из ответа API"""
    return {
        'malicious': stats.get('malicious', 0),
        'suspicious': stats.get('suspicious', 0),
        'harmless': stats.get('harmless', 0),
        'undetected': stats.get('undetected', 0)
    }
