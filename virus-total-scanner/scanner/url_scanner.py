import time
from scanner.api_client import VirusTotalAPI
from scanner.utils import base64_url_encode, parse_stats
from scanner.logger import logger

class URLScanner:
    def __init__(self):
        try:
            self.api = VirusTotalAPI()
            print("DEBUG: URLScanner инициализирован")
        except Exception as e:
            print(f"DEBUG: Ошибка инициализации API: {e}")
            raise

    def scan(self, url):
        """Проверяет URL на вредоносное ПО"""
        print(f"DEBUG: Начинаем проверку URL: {url}")
        logger.info(f"Начало проверки URL: {url}")

        # Кодируем URL для API
        url_id = base64_url_encode(url.encode())
        print(f"URL ID: {url_id}")

        try:
            print("DEBUG: Проверяем наличие отчета в VirusTotal...")
            report = self.api.get_url_report(url_id)
            self._display_results(report, url)
            return report
        except Exception as e:
            error_msg = str(e).lower()
            print(f"DEBUG: Ошибка при получении отчета: {error_msg}")
            if "not found" in error_msg:
                print("URL не найден в базе. Отправка на анализ...")
                return self._submit_and_scan(url)
            else:
                print(f"DEBUG: Другая ошибка: {e}")
                raise

    def _submit_and_scan(self, url):
        """Отправляет URL на анализ"""
        print("DEBUG: Отправляем URL на анализ...")
        submit_result = self.api.submit_url(url)
        analysis_id = submit_result["data"]["id"]
        print(f"URL отправлен. ID анализа: {analysis_id}")

        print("Ожидание результатов (30 секунд)...")
        import time
        time.sleep(30)

        print("DEBUG: Получаем результаты...")
        url_id = base64_url_encode(url.encode())
        report = self.api.get_url_report(url_id)
        self._display_results(report, url)
        return report

    def _display_results(self, report, url):
        """Отображает результаты проверки URL"""
        attributes = report.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        parsed = parse_stats(stats)
        categories = attributes.get("categories", {})

        print("\n" + "=" * 50)
        print(f"РЕЗУЛЬТАТЫ ПРОВЕРКИ URL: {url}")
        print("=" * 50)
        print(f"Вредоносных (malicious): {parsed["malicious"]}")
        print(f"Подозрительных (suspicious): {parsed["suspicious"]}")
        print(f"Безопасных (harmless): {parsed["harmless"]}")
        print(f"Не обнаружено (undetected): {parsed["undetected"]}")

        if categories:
            print("\nКатегории:")
            for source, category in categories.items():
                print(f"  - {source}: {category}")
