import os
import time
from scanner.api_client import VirusTotalAPI
from scanner.utils import compute_sha256, parse_stats
from scanner.logger import logger

class FileScanner:
    MAX_FILE_SIZE = 32 * 1024 * 1024  # 32 MB

    def __init__(self):
        try:
            self.api = VirusTotalAPI()
            print("DEBUG: FileScanner инициализирован")
        except Exception as e:
            print(f"DEBUG: Ошибка инициализации API: {e}")
            raise

    def scan(self, file_path):
        """Проверяет файл на вредоносное ПО"""
        print(f"DEBUG: Начинаем проверку файла: {file_path}")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Файл не найден: {file_path}")

        file_size = os.path.getsize(file_path)
        print(f"DEBUG: Размер файла: {file_size} байт")
        
        if file_size > self.MAX_FILE_SIZE:
            raise Exception(f"Файл превышает 32 МБ (бесплатный тариф)")

        logger.info(f"Начало проверки файла: {file_path}")

        # Вычисляем SHA-256
        file_hash = compute_sha256(file_path)
        print(f"SHA-256: {file_hash}")

        # Пытаемся получить существующий отчёт
        try:
            print("DEBUG: Проверяем наличие отчета в VirusTotal...")
            report = self.api.get_file_report(file_hash)
            print("✓ Отчёт найден в кэше VirusTotal")
            self._display_results(report)
            return report
        except Exception as e:
            error_msg = str(e).lower()
            print(f"DEBUG: Ошибка при получении отчета: {error_msg}")
            if "not found" in error_msg:
                print("Файл не найден в базе. Загрузка для анализа...")
                return self._upload_and_scan(file_path)
            else:
                print(f"DEBUG: Другая ошибка: {e}")
                raise

    def _upload_and_scan(self, file_path):
        """Загружает файл и ожидает результат"""
        print("DEBUG: Загружаем файл...")
        upload_result = self.api.upload_file(file_path)
        analysis_id = upload_result['data']['id']
        print(f"Файл загружен. ID анализа: {analysis_id}")

        print("Ожидание результатов анализа (1-2 минуты)...")
        time.sleep(60)

        print("DEBUG: Получаем результаты...")
        file_hash = compute_sha256(file_path)
        report = self.api.get_file_report(file_hash)
        self._display_results(report)
        return report

    def scan_by_hash(self, file_hash):
        """Проверяет файл по SHA-256 хешу"""
        print(f"DEBUG: Проверка по хешу: {file_hash}")
        logger.info(f"Проверка по хешу: {file_hash}")
        report = self.api.get_file_report(file_hash)
        self._display_results(report)
        return report

    def _display_results(self, report):
        """Отображает результаты анализа"""
        attributes = report.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        parsed = parse_stats(stats)

        print("\n" + "=" * 50)
        print("РЕЗУЛЬТАТЫ ПРОВЕРКИ")
        print("=" * 50)
        print(f"Вредоносных (malicious): {parsed['malicious']}")
        print(f"Подозрительных (suspicious): {parsed['suspicious']}")
        print(f"Безопасных (harmless): {parsed['harmless']}")
        print(f"Не обнаружено (undetected): {parsed['undetected']}")

        # Детальный список антивирусов
        results = attributes.get('last_analysis_results', {})
        detected = []
        for av_name, result in results.items():
            if result.get('category') == 'malicious':
                detected.append(av_name)

        if detected:
            print(f"\nАнтивирусы, обнаружившие угрозу ({len(detected)}):")
            for av in detected[:10]:
                print(f"  - {av}")
