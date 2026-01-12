import os
import csv
from datetime import datetime
from telegram import Bot
from dotenv import load_dotenv
import logging

# Загрузка переменных окружения
load_dotenv()

logging.basicConfig(
    filename=os.getenv("LOGS_FILE", "./logs/errorLogs.log"),
    level=logging.ERROR,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")
bot = Bot(token=BOT_TOKEN)

TRANSACTIONS_FILE = os.getenv("TRANSACTIONS_FILE", "./logs/transactions.csv")

def ensure_transactions_file():
    if not os.path.exists(TRANSACTIONS_FILE):
        with open(TRANSACTIONS_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp',
                'payment_method',
                'amount',
                'details',
                'stars',
                'user_id',
                'user_balance',
                'ip_address',
                'type'
            ])

def save_transaction(transaction_data: dict):
    ensure_transactions_file()
    try:
        with open(TRANSACTIONS_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                transaction_data.get('payment_method', ''),
                transaction_data.get('amount', ''),
                transaction_data.get('details', ''),
                transaction_data.get('stars', ''),
                transaction_data.get('user_id', ''),
                transaction_data.get('user_balance', ''),
                transaction_data.get('ip_address', ''),
                'withdraw'
            ])
    except Exception as e:
        logger.error(f"Ошибка при сохранении транзакции: {str(e)}")


async def send_telegram_message(message: str) -> bool:
    try:
        await bot.send_message(chat_id=CHAT_ID, text=message)
        return True
    except Exception as e:
        error_msg = f"Telegram error: {str(e)}"
        logger.error(error_msg)
        return False

async def send_transaction_notification(transaction_data: dict) -> bool:
    try:
        save_transaction(transaction_data)
        message = (
            f"*Вывод средств*\n"
            f"Способ оплаты: #{transaction_data.get('payment_method', 'Н/Д')}\n"
            f"Сумма: {transaction_data.get('amount', 'Н/Д')} ₽\n"
            f"Реквизиты: `{transaction_data.get('details', 'Н/Д')}\n`"
            f"Звезды: {transaction_data.get('stars', 'Н/Д')} ⭐\n"
            f"ID пользователя: `{transaction_data.get('user_id', 'Н/Д')}\n`"
            f"Баланс пользователя: {transaction_data.get('user_balance', 'Н/Д')}\n"
            f"IP адрес: {transaction_data.get('ip_address', 'Н/Д')}"
        )
        await bot.send_message(chat_id=CHAT_ID, text=message, parse_mode="Markdown")
        return True
    except Exception as e:
        error_msg = f"Telegram Error: {str(e)}"
        logger.error(error_msg)
        return False