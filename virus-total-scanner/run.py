#!/usr/bin/env python3
import sys
import os
import argparse

print("Запуск VirusTotal Scanner...", file=sys.stderr)

try:
    from scanner.file_scanner import FileScanner
    from scanner.url_scanner import URLScanner
    print("Модули успешно загружены", file=sys.stderr)
except Exception as e:
    print(f"Ошибка импорта: {e}", file=sys.stderr)
    sys.exit(1)

def interactive_mode():
    """Интерактивный режим с меню"""
    file_scanner = FileScanner()
    url_scanner = URLScanner()

    while True:
        print("\n" + "=" * 40)
        print("VIRUSTOTAL СКАНЕР")
        print("=" * 40)
        print("1. Проверить файл")
        print("2. Проверить URL")
        print("3. Проверить по хешу SHA-256")
        print("4. Выход")

        choice = input("\nВыберите действие (1-4): ").strip()

        if choice == '1':
            path = input("Введите путь к файлу: ").strip()
            if not path:
                print("Ошибка: путь не может быть пустым")
                continue
            if not os.path.exists(path):
                print(f"Ошибка: Файл '{path}' не найден!")
                continue
            try:
                file_scanner.scan(path)
            except Exception as e:
                print(f"Ошибка при сканировании: {e}")

        elif choice == '2':
            url = input("Введите URL: ").strip()
            if not url:
                print("Ошибка: URL не может быть пустым")
                continue
            try:
                url_scanner.scan(url)
            except Exception as e:
                print(f"Ошибка при сканировании: {e}")

        elif choice == '3':
            hash_val = input("Введите SHA-256 хеш: ").strip()
            if not hash_val:
                print("Ошибка: хеш не может быть пустым")
                continue
            try:
                file_scanner.scan_by_hash(hash_val)
            except Exception as e:
                print(f"Ошибка при сканировании: {e}")

        elif choice == '4':
            print("До свидания!")
            break
        else:
            print("Неверный выбор. Попробуйте снова.")

def main():
    parser = argparse.ArgumentParser(description='VirusTotal Scanner')
    parser.add_argument('--file', help='Путь к файлу для проверки')
    parser.add_argument('--url', help='URL для проверки')
    parser.add_argument('--hash', help='SHA-256 хеш для проверки')

    args = parser.parse_args()

    print(f"Аргументы: file={args.file}, url={args.url}, hash={args.hash}", file=sys.stderr)

    if args.file:
        if not os.path.exists(args.file):
            print(f"Ошибка: Файл '{args.file}' не найден!")
            print(f"Текущая директория: {os.getcwd()}")
            sys.exit(1)
        try:
            scanner = FileScanner()
            scanner.scan(args.file)
        except Exception as e:
            print(f"Ошибка: {e}")
            sys.exit(1)
    elif args.url:
        try:
            scanner = URLScanner()
            scanner.scan(args.url)
        except Exception as e:
            print(f"Ошибка: {e}")
            sys.exit(1)
    elif args.hash:
        try:
            scanner = FileScanner()
            scanner.scan_by_hash(args.hash)
        except Exception as e:
            print(f"Ошибка: {e}")
            sys.exit(1)
    else:
        interactive_mode()

if __name__ == "__main__":
    main()
