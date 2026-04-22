import os
import requests
import time
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

class VirusTotalAPI:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if not self.api_key:
            raise ValueError("API ключ не найден. Установите VIRUSTOTAL_API_KEY в файле .env")
        self.headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/json"
        }
        self.last_request_time = 0
        self.min_interval = 15  # 15 seconds between requests (4 per minute)

    def _rate_limit(self):
        """Ограничение частоты запросов"""
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            print(f"DEBUG: Ожидание {sleep_time:.1f} сек (rate limiting)...")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def _request(self, method, endpoint, **kwargs):
        """Выполняет HTTP запрос с обработкой ошибок"""
        url = f"{self.BASE_URL}/{endpoint}"
        self._rate_limit()
        
        try:
            print(f"DEBUG: Запрос к {url}")
            response = requests.request(method, url, headers=self.headers, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError:
            print("Ошибка: Нет подключения к интернету")
            raise Exception("Нет подключения к интернету")
        except requests.exceptions.HTTPError as e:
            if response.status_code == 429:
                print("Ошибка: Превышен лимит запросов API")
                raise Exception("Лимит запросов API превышен")
            elif response.status_code == 400:
                print(f"Ошибка: Неверный запрос - {response.text}")
                raise Exception(f"Ошибка API: {response.text}")
            else:
                print(f"Ошибка: HTTP ошибка - {e}")
                raise
        except Exception as e:
            print(f"Ошибка: Неизвестная ошибка - {e}")
            raise

    def get_file_report(self, file_hash):
        """Получает отчёт о файле по хешу"""
        print(f"DEBUG: Получение отчета для хеша: {file_hash}")
        return self._request("GET", f"files/{file_hash}")

    def upload_file(self, file_path):
        """Загружает файл для анализа"""
        print(f"DEBUG: Загрузка файла: {file_path}")
        url = f"{self.BASE_URL}/files"
        self._rate_limit()
        
        with open(file_path, "rb") as f:
            files = {"file": f}
            response = requests.post(
                url,
                headers={"x-apikey": self.api_key},
                files=files
            )
            response.raise_for_status()
            return response.json()

    def get_url_report(self, url_id):
        """Получает отчёт об URL"""
        print(f"DEBUG: Получение отчета для URL ID: {url_id}")
        return self._request("GET", f"urls/{url_id}")

    def submit_url(self, url):
        """Отправляет URL на анализ"""
        print(f"DEBUG: Отправка URL на анализ: {url}")
        url_endpoint = f"{self.BASE_URL}/urls"
        self._rate_limit()
        
        data = {"url": url}
        response = requests.post(
            url_endpoint,
            headers={"x-apikey": self.api_key},
            data=data
        )
        response.raise_for_status()
        return response.json()
