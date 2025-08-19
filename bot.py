import os
import asyncio
import logging
import requests
import sqlite3
import time
import pandas as pd
from aiogram import Bot, Dispatcher, types, F
from aiogram.enums import ParseMode
from aiogram.filters import Command
from aiogram.client.default import DefaultBotProperties
from aiogram.types import (
    ReplyKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardRemove,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
)
from dotenv import load_dotenv

# ===================== ENV & BOT ===================== #
load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
ADMIN_ID = int(os.getenv("ADMIN_ID", "0"))                 # ваш Telegram ID (числом)
ADMIN_GROUP_ID = int(os.getenv("ADMIN_GROUP_ID", "0"))     # ID группы/канала для логов

if not TELEGRAM_BOT_TOKEN or not VT_API_KEY:
    raise RuntimeError("TELEGRAM_BOT_TOKEN и VT_API_KEY обязательны в .env")

bot = Bot(token=TELEGRAM_BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
dp = Dispatcher()
logging.basicConfig(level=logging.INFO)

# ===================== VirusTotal ===================== #
VT_FILE_SCAN_URL = "https://www.virustotal.com/api/v3/files"
VT_URL_SCAN_URL = "https://www.virustotal.com/api/v3/urls"
VT_HEADERS = {"x-apikey": VT_API_KEY}

# ===================== LIMITS & CONSTANTS ===================== #
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
CACHE_TTL_DAYS = 7
CACHE_CLEANUP_INTERVAL_SEC = 12 * 60 * 60  # каждые 12 часов
DOWNLOADS_DIR = "downloads"

# ===================== UI ===================== #
lang_keyboard = ReplyKeyboardMarkup(
    keyboard=[[KeyboardButton(text="🇷🇺 Русский"), KeyboardButton(text="🇺🇿 O'zbek")]],
    resize_keyboard=True
)

def get_phone_request_keyboard(lang: str) -> ReplyKeyboardMarkup:
    text = "Отправить номер телефона 📱" if lang == "ru" else "Telefon raqamini yuborish 📱"
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=text, request_contact=True)]],
        resize_keyboard=True,
        one_time_keyboard=True
    )

user_lang: dict[int, str] = {}

# FSM-память для админ-действий (простая)
admin_waiting_action: dict[int, str] = {}  # {admin_id: "block"|"unblock"}

# ===================== DB ===================== #
conn = sqlite3.connect("cache.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS cache (
        key TEXT PRIMARY KEY,
        analysis_id TEXT,
        verdict TEXT,
        timestamp INTEGER
    )
    """
)
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS authorized_users (
        user_id INTEGER PRIMARY KEY,
        phone TEXT,
        lang TEXT,
        authorized_at INTEGER,
        blocked INTEGER DEFAULT 0
    )
    """
)
conn.commit()

# ===================== TEXTS ===================== #
def get_msg(key, lang):
    texts = {
        "start": {
            "ru": "👋 Привет! Пришлите мне файл или ссылку — я проверю их на вирусы.",
            "uz": "👋 Salom! Fayl yoki havolani yuboring — men ularni virusga tekshiraman."
        },
        "choose_lang": {
            "ru": "🇷🇺 Пожалуйста, выбери язык:",
            "uz": "🇺🇿 Iltimos, tilni tanlang:"
        },
        "auth_request": {
            "ru": "⚠️ Пожалуйста, авторизуйтесь, нажмите на кнопку отправить номер телефона.",
            "uz": "⚠️ Iltimos, tizimga kiring, telefon raqamini yuborish tugmasini bosing."
        },
        "auth_thanks": {
            "ru": "✅ Спасибо за авторизацию!",
            "uz": "✅ Avtorizatsiya uchun rahmat!"
        },
        "blocked": {
            "ru": "🚫 Вы заблокированы администратором.",
            "uz": "🚫 Siz administrator tomonidan bloklangansiz."
        },
        "scanning_file": {"ru": "📥 Сканирую файл...", "uz": "📥 Fayl skanerlanyapti..."},
        "scanning_url": {"ru": "🌐 Проверяю ссылку...", "uz": "🌐 Havola tekshirilmoqda..."},
        "file_error": {"ru": "❌ Ошибка при отправке файла.", "uz": "❌ Faylni yuborishda xatolik yuz berdi."},
        "file_too_big": {"ru": "⚠️ Файл слишком большой. Максимум 20 МБ.", "uz": "⚠️ Fayl juda katta. Maksimal hajm 20 MB."},
        "url_error": {"ru": "❌ Не удалось отправить ссылку.", "uz": "❌ Havolani yuborib bo'lmadi."},
        "no_support": {"ru": "❌ Этот тип сообщений не поддерживается.", "uz": "❌ Bu turdagi xabarlar qo'llab-quvvatlanmaydi."},
        "result_safe": {"ru": "✅ <b>Объект безопасен</b>", "uz": "✅ <b>Obyekt xavfsiz</b>"},
        "result_danger": {"ru": "⚠️ <b>Обнаружены угрозы!</b>", "uz": "⚠️ <b>Xavfli holatlar aniqlandi!</b>"},
        "result_stats": {"ru": "🛡️ <b>Результаты:</b>", "uz": "🛡️ <b>Natijalar:</b>"},
        "malicious_label": {"ru": "Вредоносных", "uz": "Zararli"},
        "suspicious_label": {"ru": "Подозрительных", "uz": "Shubhali"},
        "harmless_label": {"ru": "Безопасных", "uz": "Xavfsiz"},
        "undetected_label": {"ru": "Неопределённых", "uz": "Aniqlanmagan"},
        "admin_only": {"ru": "Эта команда только для админа.", "uz": "Bu buyruq faqat adminlar uchun."},
    }
    return texts.get(key, {}).get(lang, "...")

# ===================== HELPERS ===================== #
def get_auth_state(user_id: int) -> str:
    cursor.execute("SELECT blocked FROM authorized_users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    if row is None:
        return "unauthorized"
    return "blocked" if row[0] == 1 else "authorized"

def is_authorized_active(user_id: int) -> bool:
    return get_auth_state(user_id) == "authorized"

def save_authorization(user_id: int, phone: str, lang: str):
    ts = int(time.time())
    cursor.execute(
        """
        INSERT OR REPLACE INTO authorized_users (user_id, phone, lang, authorized_at, blocked)
        VALUES (
            ?, ?, ?, ?, COALESCE((SELECT blocked FROM authorized_users WHERE user_id = ?), 0)
        )
        """,
        (user_id, phone, lang, ts, user_id),
    )
    conn.commit()

async def cache_result(key: str, analysis_id: str, verdict: str):
    cursor.execute(
        "INSERT OR REPLACE INTO cache (key, analysis_id, verdict, timestamp) VALUES (?, ?, ?, ?)",
        (key, analysis_id, verdict, int(time.time())),
    )
    conn.commit()

async def get_cached_result(key: str):
    cursor.execute("SELECT analysis_id, verdict FROM cache WHERE key = ?", (key,))
    row = cursor.fetchone()
    if row:
        return row[0], row[1]
    return None, None

async def safe_send_admin(text: str):
    if ADMIN_GROUP_ID == 0:
        return
    try:
        await bot.send_message(ADMIN_GROUP_ID, text, disable_web_page_preview=True)
    except Exception as e:
        logging.warning(f"ADMIN_GROUP send failed: {e}")

# Очистка кэша старше 7 дней с уведомлением
async def cleanup_cache():
    while True:
        try:
            week_ago = int(time.time()) - CACHE_TTL_DAYS * 24 * 60 * 60
            cursor.execute("DELETE FROM cache WHERE timestamp < ?", (week_ago,))
            deleted = cursor.rowcount
            conn.commit()
            if deleted > 0:
                msg = f"🧹 Старый кэш очищен: {deleted} записей удалено"
                logging.info(msg)
                await safe_send_admin(msg)
        except Exception as e:
            logging.error(f"Ошибка при очистке кэша: {e}")
        await asyncio.sleep(CACHE_CLEANUP_INTERVAL_SEC)

# ===================== VirusTotal ===================== #
async def vt_poll_result(analysis_id: str, max_wait_sec: int = 60, step_sec: float = 2.0):
    """Пуллим статус анализа до 'completed' или таймаута. Возвращает dict attributes или None."""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    waited = 0.0
    while waited <= max_wait_sec:
        try:
            resp = requests.get(url, headers=VT_HEADERS, timeout=15)
            if resp.status_code == 200:
                j = resp.json()
                attrs = j["data"]["attributes"]
                status = attrs.get("status")
                if status == "completed":
                    return attrs
            else:
                logging.warning(f"VT poll status: {resp.status_code} {resp.text}")
        except Exception as e:
            logging.error(f"VT poll error: {e}")
        await asyncio.sleep(step_sec)
        waited += step_sec
    return None

# ===================== ADMIN COMMANDS ===================== #
@dp.message(Command("block"))
async def cmd_block(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return await message.answer(get_msg("admin_only", "ru"))
    parts = message.text.strip().split()
    if len(parts) != 2 or not parts[1].isdigit():
        return await message.answer("⚠️ Использование: <code>/block 123456789</code>")
    uid = int(parts[1])
    cursor.execute("UPDATE authorized_users SET blocked = 1 WHERE user_id = ?", (uid,))
    conn.commit()
    await message.answer(f"🚫 Пользователь <code>{uid}</code> заблокирован.")
    try:
        await bot.send_message(uid, get_msg("blocked", "ru"))
    except Exception:
        pass
    await safe_send_admin(f"🛑 Админ заблокировал пользователя <code>{uid}</code>.")

@dp.message(Command("unblock"))
async def cmd_unblock(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return await message.answer(get_msg("admin_only", "ru"))
    parts = message.text.strip().split()
    if len(parts) != 2 or not parts[1].isdigit():
        return await message.answer("⚠️ Использование: <code>/unblock 123456789</code>")
    uid = int(parts[1])
    cursor.execute("UPDATE authorized_users SET blocked = 0 WHERE user_id = ?", (uid,))
    conn.commit()
    await message.answer(f"✅ Пользователь <code>{uid}</code> разблокирован.")
    try:
        await bot.send_message(uid, "✅ Ваша блокировка снята.")
    except Exception:
        pass
    await safe_send_admin(f"♻️ Админ разблокировал пользователя <code>{uid}</code>.")

@dp.message(Command("users_count"))
async def users_count(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return await message.answer(get_msg("admin_only", "ru"))
    cursor.execute("SELECT COUNT(*) FROM authorized_users")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM authorized_users WHERE blocked=1")
    blocked = cursor.fetchone()[0]
    active = total - blocked
    await message.answer(
        f"📊 Статистика\n\n👥 Всего: <b>{total}</b>\n✅ Активных: <b>{active}</b>\n🚫 Заблокированных: <b>{blocked}</b>"
    )

@dp.message(Command("export_users"))
async def export_users(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return await message.answer(get_msg("admin_only", "ru"))
    df = pd.read_sql_query(
        "SELECT user_id, phone, lang, datetime(authorized_at,'unixepoch','localtime') AS authorized_at, blocked FROM authorized_users",
        conn,
    )
    if df.empty:
        return await message.answer("📭 В базе пока нет пользователей.")
    path = "users.xlsx"
    df.to_excel(path, index=False)
    await message.answer_document(types.FSInputFile(path))

# ===================== ADMIN MENU (Inline) ===================== #
def admin_menu_kb() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="👥 Статистика", callback_data="admin:stats")],
        [InlineKeyboardButton(text="📤 Экспорт пользователей", callback_data="admin:export")],
        [
            InlineKeyboardButton(text="🚫 Блокировать", callback_data="admin:block"),
            InlineKeyboardButton(text="✅ Разблокировать", callback_data="admin:unblock"),
        ],
    ])
    return kb

@dp.message(Command("admin"))
async def admin_menu(message: types.Message):
    if message.from_user.id != ADMIN_ID:
        return await message.answer(get_msg("admin_only", "ru"))
    await message.answer("🛠 Админ-меню", reply_markup=admin_menu_kb())

@dp.callback_query(F.data.startswith("admin:"))
async def on_admin_callback(call: types.CallbackQuery):
    if call.from_user.id != ADMIN_ID:
        return await call.answer("Нет доступа", show_alert=True)

    action = call.data.split(":", 1)[1]
    if action == "stats":
        cursor.execute("SELECT COUNT(*) FROM authorized_users")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM authorized_users WHERE blocked=1")
        blocked = cursor.fetchone()[0]
        active = total - blocked
        return await call.message.edit_text(
            f"📊 Статистика\n\n👥 Всего: <b>{total}</b>\n✅ Активных: <b>{active}</b>\n🚫 Заблокированных: <b>{blocked}</b>",
            reply_markup=admin_menu_kb(),
        )
    elif action == "export":
        df = pd.read_sql_query(
            "SELECT user_id, phone, lang, datetime(authorized_at,'unixepoch','localtime') AS authorized_at, blocked FROM authorized_users",
            conn,
        )
        if df.empty:
            return await call.answer("Нет данных", show_alert=True)
        path = "users.xlsx"
        df.to_excel(path, index=False)
        await call.message.answer_document(types.FSInputFile(path))
        return await call.answer("Готово")
    elif action in ("block", "unblock"):
        admin_waiting_action[call.from_user.id] = action
        verb = "ID пользователя для блокировки" if action == "block" else "ID пользователя для разблокировки"
        await call.message.answer(f"✍️ Введите {verb}: <code>/id</code>")
        return await call.answer()

@dp.message(F.text.regexp(r"^\d{5,}$"))
async def admin_enter_user_id(message: types.Message):
    # Ввод ID после выбора в админ-меню
    if message.from_user.id != ADMIN_ID:
        return
    action = admin_waiting_action.get(message.from_user.id)
    if not action:
        return
    uid = int(message.text.strip())
    if action == "block":
        cursor.execute("UPDATE authorized_users SET blocked = 1 WHERE user_id = ?", (uid,))
        conn.commit()
        await message.answer(f"🚫 Пользователь <code>{uid}</code> заблокирован.")
        try:
            await bot.send_message(uid, get_msg("blocked", "ru"))
        except Exception:
            pass
        await safe_send_admin(f"🛑 Админ заблокировал пользователя <code>{uid}</code>.")
    else:
        cursor.execute("UPDATE authorized_users SET blocked = 0 WHERE user_id = ?", (uid,))
        conn.commit()
        await message.answer(f"✅ Пользователь <code>{uid}</code> разблокирован.")
        try:
            await bot.send_message(uid, "✅ Ваша блокировка снята.")
        except Exception:
            pass
        await safe_send_admin(f"♻️ Админ разблокировал пользователя <code>{uid}</code>.")
    admin_waiting_action.pop(message.from_user.id, None)

# ===================== USER FLOW ===================== #
@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    user_lang.pop(message.from_user.id, None)
    await message.answer(
        f"{get_msg('choose_lang', 'ru')}\n{get_msg('choose_lang', 'uz')}",
        reply_markup=lang_keyboard,
    )

@dp.message(F.text.in_(["🇷🇺 Русский", "🇺🇿 O'zbek"]))
async def set_language(message: types.Message):
    lang = "ru" if "Русский" in message.text else "uz"
    user_lang[message.from_user.id] = lang

    state = get_auth_state(message.from_user.id)
    if state == "unauthorized":
        await message.answer(get_msg("auth_request", lang), reply_markup=get_phone_request_keyboard(lang))
    elif state == "blocked":
        await message.answer(get_msg("blocked", lang))
    else:
        await message.answer(get_msg("start", lang))

@dp.message(F.contact)
async def contact_handler(message: types.Message):
    contact = message.contact
    uid = message.from_user.id
    lang = user_lang.get(uid, "ru")

    if contact.user_id != uid:
        return await message.answer("⚠️ Пожалуйста, отправьте именно <b>свой</b> номер телефона.")

    save_authorization(uid, contact.phone_number, lang)
    state = get_auth_state(uid)
    if state == "blocked":
        return await message.answer(get_msg("blocked", lang))

    await message.answer(get_msg("auth_thanks", lang), reply_markup=ReplyKeyboardRemove())
    await message.answer(get_msg("start", lang))
    await safe_send_admin(
        f"🆕 Авторизован пользователь:\n• ID: <code>{uid}</code>\n• Phone: <code>{contact.phone_number}</code>\n• Nikname: <code>{message.from_user.username}</code>\n• Lang: <b>{lang}</b>"
    )

async def send_result_message(message: types.Message, attributes: dict, lang: str, cache_key: str = None, analysis_id: str = None, context_title: str = "-"):
    stats = attributes.get("stats", {}) if attributes else {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))

    verdict = get_msg("result_safe", lang) if (malicious == 0 and suspicious == 0) else get_msg("result_danger", lang)

    text = (
        f"{verdict}\n\n"
        f"{get_msg('result_stats', lang)}\n"
        f"🔴 <b>{get_msg('malicious_label', lang)}:</b> {malicious}\n"
        f"🟡 <b>{get_msg('suspicious_label', lang)}:</b> {suspicious}\n"
        f"🟢 <b>{get_msg('harmless_label', lang)}:</b> {harmless}\n"
        f"⚪ <b>{get_msg('undetected_label', lang)}:</b> {undetected}\n"
    )
    await message.answer(text, disable_web_page_preview=True)

    if cache_key and analysis_id:
        await cache_result(cache_key, analysis_id, text)

    await safe_send_admin(
        f"📣 Результат сканирования ({context_title})\n"
        f"• User: <code>{message.from_user.id}</code>\n"
        f"• Malicious: <b>{malicious}</b>, Suspicious: <b>{suspicious}</b>, Harmless: <b>{harmless}</b>, Undetected: <b>{undetected}</b>"
    )

# --------------------- FILE HANDLER --------------------- #
@dp.message(F.document)
async def handle_file(message: types.Message):
    lang = user_lang.get(message.from_user.id, "ru")
    state = get_auth_state(message.from_user.id)
    if state == "unauthorized":
        return await message.answer(get_msg("auth_request", lang), reply_markup=get_phone_request_keyboard(lang))
    if state == "blocked":
        return await message.answer(get_msg("blocked", lang))

    if message.document.file_size > MAX_FILE_SIZE:
        return await message.answer(get_msg("file_too_big", lang))

    await message.answer(get_msg("scanning_file", lang))

    cache_key = f"file:{message.document.file_unique_id}:{lang}"
    cached_id, cached_text = await get_cached_result(cache_key)
    if cached_id:
        return await message.answer(cached_text, disable_web_page_preview=True)

    await safe_send_admin(
        f"📥 Пользователь <code>{message.from_user.id}</code> прислал файл: <b>{message.document.file_name}</b> ({message.document.file_size} байт)"
    )

    # Скачиваем во временный файл
    try:
        file_info = await bot.get_file(message.document.file_id)
        os.makedirs(DOWNLOADS_DIR, exist_ok=True)
        local_path = os.path.join(DOWNLOADS_DIR, f"{message.document.file_id}_{message.document.file_name}")
        await bot.download_file(file_info.file_path, local_path)
    except Exception as e:
        logging.error(f"Telegram file download error: {e}")
        return await message.answer(get_msg("file_error", lang))

    # Отправляем на VT
    try:
        with open(local_path, "rb") as f:
            files = {"file": (message.document.file_name, f)}
            res = requests.post(VT_FILE_SCAN_URL, headers=VT_HEADERS, files=files, timeout=120)
        if res.status_code != 200:
            logging.error(f"VT file upload failed: {res.status_code} {res.text}")
            try:
                os.remove(local_path)
            except Exception:
                pass
            return await message.answer(get_msg("file_error", lang))
        analysis_id = res.json()["data"]["id"]
    except Exception as e:
        logging.error(f"VT file upload exception: {e}")
        try:
            os.remove(local_path)
        except Exception:
            pass
        return await message.answer(get_msg("file_error", lang))

    attrs = await vt_poll_result(analysis_id)
    try:
        os.remove(local_path)  # автоудаление временного файла
    except Exception:
        pass

    if not attrs:
        return await message.answer("⌛️ Анализ ещё выполняется, попробуйте позже." if lang == "ru" else "⌛️ Tahlil hali davom etmoqda, keyinroq urinib ko'ring.")

    await send_result_message(
        message, attrs, lang, cache_key, analysis_id, context_title=f"FILE: {message.document.file_name}"
    )

# --------------------- PHOTO HANDLER --------------------- #
@dp.message(F.photo)
async def handle_photo(message: types.Message):
    lang = user_lang.get(message.from_user.id, "ru")
    state = get_auth_state(message.from_user.id)
    if state == "unauthorized":
        return await message.answer(get_msg("auth_request", lang), reply_markup=get_phone_request_keyboard(lang))
    if state == "blocked":
        return await message.answer(get_msg("blocked", lang))

    await message.answer(get_msg("scanning_file", lang))

    photo = message.photo[-1]
    cache_key = f"photo:{photo.file_unique_id}:{lang}"
    cached_id, cached_text = await get_cached_result(cache_key)
    if cached_id:
        return await message.answer(cached_text, disable_web_page_preview=True)

    await safe_send_admin(
        f"🖼 Пользователь <code>{message.from_user.id}</code> прислал фото: (file_unique_id={photo.file_unique_id})"
    )

    try:
        file_info = await bot.get_file(photo.file_id)
        os.makedirs(DOWNLOADS_DIR, exist_ok=True)
        local_path = os.path.join(DOWNLOADS_DIR, f"{photo.file_id}.jpg")
        await bot.download_file(file_info.file_path, local_path)
    except Exception as e:
        logging.error(f"Telegram photo download error: {e}")
        return await message.answer(get_msg("file_error", lang))

    try:
        with open(local_path, "rb") as f:
            files = {"file": ("photo.jpg", f)}
            res = requests.post(VT_FILE_SCAN_URL, headers=VT_HEADERS, files=files, timeout=120)
        if res.status_code != 200:
            logging.error(f"VT photo upload failed: {res.status_code} {res.text}")
            try:
                os.remove(local_path)
            except Exception:
                pass
            return await message.answer(get_msg("file_error", lang))
        analysis_id = res.json()["data"]["id"]
    except Exception as e:
        logging.error(f"VT photo upload exception: {e}")
        try:
            os.remove(local_path)
        except Exception:
            pass
        return await message.answer(get_msg("file_error", lang))

    attrs = await vt_poll_result(analysis_id)
    try:
        os.remove(local_path)
    except Exception:
        pass

    if not attrs:
        return await message.answer("⌛️ Анализ ещё выполняется, попробуйте позже." if lang == "ru" else "⌛️ Tahlil hali davom etmoqda, keyinroq urinib ko'ring.")

    await send_result_message(message, attrs, lang, cache_key, analysis_id, context_title="PHOTO")

# --------------------- URL HANDLER --------------------- #
@dp.message(F.text.startswith("http"))
async def handle_url(message: types.Message):
    lang = user_lang.get(message.from_user.id, "ru")
    state = get_auth_state(message.from_user.id)
    if state == "unauthorized":
        return await message.answer(get_msg("auth_request", lang), reply_markup=get_phone_request_keyboard(lang))
    if state == "blocked":
        return await message.answer(get_msg("blocked", lang))

    await message.answer(get_msg("scanning_url", lang))

    url_text = message.text.strip()
    cache_key = f"url:{url_text}:{lang}"
    cached_id, cached_text = await get_cached_result(cache_key)
    if cached_id:
        return await message.answer(cached_text, disable_web_page_preview=True)

    await safe_send_admin(
        f"🔗 Пользователь <code>{message.from_user.id}</code> отправил URL: <code>{url_text}</code>"
    )

    try:
        resp = requests.post(VT_URL_SCAN_URL, headers=VT_HEADERS, data={"url": url_text}, timeout=60)
        if resp.status_code != 200:
            logging.error(f"VT url submit failed: {resp.status_code} {resp.text}")
            return await message.answer(get_msg("url_error", lang))
        analysis_id = resp.json()["data"]["id"]
    except Exception as e:
        logging.error(f"VT url submit exception: {e}")
        return await message.answer(get_msg("url_error", lang))

    attrs = await vt_poll_result(analysis_id)
    if not attrs:
        return await message.answer("⌛️ Анализ ещё выполняется, попробуйте позже." if lang == "ru" else "⌛️ Tahlil hali davom etmoqda, keyinroq urinib ko'ring.")

    await send_result_message(message, attrs, lang, cache_key, analysis_id, context_title=f"URL: {url_text}")

# --------------------- FALLBACK --------------------- #
@dp.message()
async def unsupported(message: types.Message):
    lang = user_lang.get(message.from_user.id, "ru")
    state = get_auth_state(message.from_user.id)
    if state == "unauthorized":
        return await message.answer(get_msg("auth_request", lang), reply_markup=get_phone_request_keyboard(lang))
    if state == "blocked":
        return await message.answer(get_msg("blocked", lang))
    await message.answer(get_msg("no_support", lang))

# ===================== RUN ===================== #
async def main():
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)
    asyncio.create_task(cleanup_cache())  # запуск фоновой очистки кэша
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        conn.close()
