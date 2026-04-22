ИНСТРУКЦИЯ ПО ЗАПУСКУ ПРОЕКТА 1. Скопируйте репозиторий 2. Откройте папку с файлами в VSC 3. Установите зависимости pip install requests python-dotenv
pip install pytest 4. Создайте в корне проекта файл .env со следующим содержимым:VIRUSTOTAL_API_KEY=ваш_реальный_api_ключ 5. Запустите программу python run.py
6. Запустите тесты pytest -v
ОТЧЕТ 1. Проверка чистого файла (результат: безвреден)
<img width="1138" height="682" alt="1 тест по пути" src="https://github.com/user-attachments/assets/fdc6f77a-1d81-498e-9190-e265751cfaf3" />
2. Проверка известного вредоносного файла (например, тестового файла EICAR)
<img width="1158" height="811" alt="eicar" src="https://github.com/user-attachments/assets/04de07d9-66f8-4dc3-a5b4-32a31376a4d0" />
3. Проверка URL
<img width="968" height="722" alt="2 по url" src="https://github.com/user-attachments/assets/61cefe05-21e9-40c9-bbf2-32ad74c68259" />
