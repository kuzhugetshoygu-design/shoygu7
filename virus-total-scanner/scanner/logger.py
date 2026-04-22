import logging

def setup_logger():
    """Настройка логгера"""
    logging.basicConfig(
        filename='virustotal.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

# Создаем глобальный логгер
logger = setup_logger()
