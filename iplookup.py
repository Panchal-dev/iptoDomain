import os
import time
import math
import random
import ipaddress
import requests
import telebot
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from flask import Flask
import logging
from datetime import datetime
import tempfile
import shutil

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("iplookup.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Constants
HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
]
REQUEST_TIMEOUT = 10
MAX_RETRIES = 2
REQUESTS_PER_SECOND = 0.5  # Reduced for Railway free tier
REVIP_API_URL = "https://api.revip.workers.dev/"
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_IDS = list(map(int, os.environ.get("ALLOWED_IDS", "").split(","))) if os.environ.get("ALLOWED_IDS") else []

# Flask app for webhook
app = Flask(__name__)
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# Rate Limiter
class RateLimiter:
    def __init__(self, requests_per_second: float):
        self.delay = 1.0 / requests_per_second
        self.last_request = 0
        self._lock = Lock()

    def acquire(self):
        with self._lock:
            now = time.time()
            if now - self.last_request < self.delay:
                time.sleep(self.delay - (now - self.last_request))
            self.last_request = time.time()

# Request Handler
class RequestHandler:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.rate_limiter = RateLimiter(REQUESTS_PER_SECOND)

    def _get_headers(self):
        headers = HEADERS.copy()
        headers["user-agent"] = random.choice(USER_AGENTS)
        return headers

    def get(self, url, timeout=REQUEST_TIMEOUT):
        self.rate_limiter.acquire()
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.get(url, timeout=timeout, headers=self._get_headers())
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                logger.warning(f"GET request failed for {url}: {e}. Attempt {attempt + 1}/{MAX_RETRIES + 1}")
                if attempt == MAX_RETRIES:
                    return None
                time.sleep(2 ** attempt)
        return None

    def post(self, url, data=None, json=None, timeout=REQUEST_TIMEOUT):
        self.rate_limiter.acquire()
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.post(url, data=data, json=json, timeout=timeout, headers=self._get_headers())
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                logger.warning(f"POST request failed for {url}: {e}. Attempt {attempt + 1}/{MAX_RETRIES + 1}")
                if attempt == MAX_RETRIES:
                    return None
                time.sleep(2 ** attempt)
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()

# Domain Source base class
class DomainSource(RequestHandler):
    def __init__(self, name):
        super().__init__()
        self.name = name

    def fetch(self, ip):
        raise NotImplementedError

# RapidDNS Source
class RapidDNSSource(DomainSource):
    def __init__(self):
        super().__init__("RapidDNS")

    def _extract_domains_from_page(self, soup):
        domains = set()
        try:
            for row in soup.find_all('tr'):
                tds = row.find_all('td')
                if tds and len(tds) > 0:
                    domain = tds[0].text.strip()
                    if domain:
                        domains.add(domain)
        except Exception as e:
            logger.error(f"Error extracting domains from RapidDNS: {e}")
        return domains

    def _get_total_results(self, soup):
        try:
            span = soup.find("span", style="color: #39cfca; ")
            if span and span.text.strip().isdigit():
                return int(span.text.strip())
            return 0
        except Exception:
            return 0

    def fetch(self, ip):
        domains = set()
        try:
            response = self.get(f"https://rapiddns.io/sameip/{ip}")
            if response:
                soup = BeautifulSoup(response.content, 'html.parser')
                domains.update(self._extract_domains_from_page(soup))
                total_results = self._get_total_results(soup)
                if total_results > 100:
                    total_pages = math.ceil(total_results / 100)
                    for page in range(2, total_pages + 1):
                        response = self.get(f"https://rapiddns.io/sameip/{ip}?page={page}")
                        if response:
                            soup = BeautifulSoup(response.content, 'html.parser')
                            domains.update(self._extract_domains_from_page(soup))
        except Exception as e:
            logger.error(f"Error fetching from RapidDNS for IP {ip}: {e}")
        return domains

# YouGetSignal Source
class YouGetSignalSource(DomainSource):
    def __init__(self):
        super().__init__("YouGetSignal")

    def fetch(self, ip):
        domains = set()
        try:
            data = {'remoteAddress': ip, 'key': '', '_': ''}
            response = self.post("https://domains.yougetsignal.com/domains.php", data=data)
            if response and response.json().get("status") == "Success":
                domains.update(
                    domain[0] for domain in response.json().get("domainArray", [])
                    if domain and len(domain) > 0
                )
        except Exception as e:
            logger.error(f"Error fetching from YouGetSignal for IP {ip}: {e}")
        return domains

# RevIP Source
class RevIPSource(DomainSource):
    def __init__(self):
        super().__init__("RevIP")

    def fetch(self, ip):
        domains = set()
        try:
            response = self.post(REVIP_API_URL, json={"ips": [ip]})
            if response:
                data = response.json()
                result = data.get(ip, {})
                if result.get("status") == "success":
                    domains.update(result.get("domains", []))
                else:
                    logger.warning(f"RevIP API error for IP {ip}: {result.get('message', 'Unknown error')}")
        except Exception as e:
            logger.error(f"Error fetching from RevIP for IP {ip}: {e}")
        return domains

# Get scrapers
def get_scrapers():
    return [
        RapidDNSSource(),
        YouGetSignalSource(),
        RevIPSource()
    ]

# Process IPs from file
def process_file(file_path):
    ips = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        ipaddress.ip_address(line)
                        ips.append(line)
                    except ValueError:
                        try:
                            network = ipaddress.ip_network(line, strict=False)
                            ips.extend(str(ip) for ip in network.hosts())
                        except ValueError:
                            logger.warning(f"Invalid IP or CIDR: {line}")
        return list(set(ips))
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return []

# Split large file into parts
def split_file(file_path, max_size=MAX_FILE_SIZE):
    output_files = []
    try:
        base_name = os.path.splitext(file_path)[0]
        part_number = 1
        current_file = None
        current_size = 0
        line_buffer = []

        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line_size = len(line.encode('utf-8'))
                if current_size + line_size > max_size or current_file is None:
                    if current_file:
                        current_file.close()
                        output_files.append(f"{base_name}_part{part_number}.txt")
                        part_number += 1
                        current_size = 0
                    current_file = open(f"{base_name}_part{part_number}.txt", 'w', encoding='utf-8')
                current_file.write(line)
                current_size += line_size
                line_buffer.append(line)

        if current_file:
            current_file.close()
            output_files.append(f"{base_name}_part{part_number}.txt")

        if not output_files:
            output_files.append(file_path)

        return output_files
    except Exception as e:
        logger.error(f"Error splitting file {file_path}: {e}")
        return [file_path]

# IP Lookup class
class IPLookup:
    def __init__(self):
        self.scrapers = get_scrapers()

    def _fetch_from_source(self, source, ip):
        try:
            domains = source.fetch(ip)
            logger.info(f"Fetched {len(domains)} domains from {source.name} for IP {ip}")
            return domains
        except Exception as e:
            logger.error(f"Error fetching from {source.name} for IP {ip}: {e}")
            return set()

    def _save_domains(self, domains, output_file):
        if domains:
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(domains)) + "\n")
            except Exception as e:
                logger.error(f"Error saving domains to {output_file}: {e}")
                return False
        return True

    def process_ip(self, ip):
        try:
            with ThreadPoolExecutor(max_workers=len(self.scrapers)) as executor:
                futures = [
                    executor.submit(self._fetch_from_source, source, ip)
                    for source in self.scrapers
                ]
                results = [f.result() for f in as_completed(futures)]
            domains = set().union(*results) if results else set()
            logger.info(f"Processed IP {ip}: {len(domains)} domains found")
            return domains
        except Exception as e:
            logger.error(f"Error processing IP {ip}: {e}")
            return set()

    def run(self, ips, output_file):
        if not ips:
            return False, "No valid IPs provided"

        all_domains = set()
        try:
            with ThreadPoolExecutor(max_workers=3) as executor:  # Reduced for Railway
                futures = [executor.submit(self.process_ip, ip) for ip in ips]
                for future in as_completed(futures):
                    try:
                        domains = future.result()
                        all_domains.update(domains)
                    except Exception as e:
                        logger.error(f"Error in IP processing thread: {e}")

            if not all_domains:
                return False, "No domains found for the provided IPs"

            success = self._save_domains(all_domains, output_file)
            if not success:
                return False, "Failed to save domains to file"

            output_files = split_file(output_file)
            return True, output_files
        except Exception as e:
            logger.error(f"Error running IP lookup: {e}")
            return False, str(e)

# User state
user_state = {}  # {chat_id: {'step': str, 'processing': bool}}

# Telegram bot handlers
@bot.message_handler(commands=['start'])
def handle_start(message):
    chat_id = message.chat.id
    if chat_id not in ALLOWED_IDS:
        bot.reply_to(message, "🚫 Unauthorized access!")
        logger.info(f"Unauthorized access by chat_id {chat_id}")
        return

    user_state[chat_id] = {'step': 'awaiting_file', 'processing': False}
    bot.reply_to(
        message,
        "🎯 Welcome to IP Lookup Bot!\n\n"
        "📤 Please upload a `.txt` file containing IPs or CIDRs (one per line).\n"
        "💡 Example:\n```\n192.168.1.1\n10.0.0.0/24\n```\n"
        "❌ No other input is needed."
    )
    logger.info(f"User {chat_id} started bot")

@bot.message_handler(content_types=['document'])
def handle_document(message):
    chat_id = message.chat.id
    if chat_id not in ALLOWED_IDS:
        bot.reply_to(message, "🚫 Unauthorized access!")
        logger.info(f"Unauthorized access by chat_id {chat_id}")
        return

    if chat_id not in user_state or user_state[chat_id]['step'] != 'awaiting_file':
        bot.reply_to(message, "❌ Please start with /start.")
        return

    if user_state[chat_id]['processing']:
        bot.reply_to(message, "⏳ Already processing a file. Please wait.")
        return

    if not message.document.file_name.endswith('.txt'):
        bot.reply_to(message, "❌ Please upload a `.txt` file.")
        return

    try:
        user_state[chat_id]['processing'] = True
        processing_message = bot.reply_to(message, "⏳ Downloading and processing your file...")

        # Download file
        file_info = bot.get_file(message.document.file_id)
        file_url = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_info.file_path}"
        response = requests.get(file_url, timeout=10)
        response.raise_for_status()

        # Save to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as temp_file:
            temp_file.write(response.content)
            temp_file_path = temp_file.name

        # Process IPs
        ips = process_file(temp_file_path)
        if not ips:
            bot.edit_message_text("❌ No valid IPs or CIDRs found in the file.", chat_id, processing_message.message_id)
            user_state[chat_id]['processing'] = False
            os.unlink(temp_file_path)
            return

        # Run IP lookup
        output_dir = tempfile.mkdtemp()
        output_file = os.path.join(output_dir, f"domains_{chat_id}_{int(time.time())}.txt")
        iplookup = IPLookup()
        success, result = iplookup.run(ips, output_file)

        if not success:
            bot.edit_message_text(f"❌ Error: {result}", chat_id, processing_message.message_id)
            user_state[chat_id]['processing'] = False
            shutil.rmtree(output_dir, ignore_errors=True)
            os.unlink(temp_file_path)
            return

        # Send output files
        output_files = result
        bot.edit_message_text(
            f"✅ Found {len(all_domains)} domains!\n\n📤 Sending output file(s)...",
            chat_id, processing_message.message_id
        )

        for output_file in output_files:
            with open(output_file, 'rb') as f:
                bot.send_document(chat_id, f, caption="Domains found (one per line).")

        bot.send_message(
            chat_id,
            "🎉 Processing complete!\n\n🔄 Upload another `.txt` file or use /start to begin again."
        )

        # Cleanup
        user_state[chat_id]['processing'] = False
        shutil.rmtree(output_dir, ignore_errors=True)
        os.unlink(temp_file_path)

    except Exception as e:
        logger.error(f"Error handling document for chat_id {chat_id}: {e}")
        bot.edit_message_text(
            f"❌ An unexpected error occurred: {str(e)}\n\n🔄 Please try again with /start.",
            chat_id, processing_message.message_id
        )
        user_state[chat_id]['processing'] = False
        if 'temp_file_path' in locals():
            try:
                os.unlink(temp_file_path)
            except:
                pass
        if 'output_dir' in locals():
            shutil.rmtree(output_dir, ignore_errors=True)

@bot.message_handler(commands=['cancel'])
def handle_cancel(message):
    chat_id = message.chat.id
    if chat_id not in ALLOWED_IDS:
        bot.reply_to(message, "🚫 Unauthorized access!")
        return

    if chat_id in user_state and user_state[chat_id]['processing']:
        user_state[chat_id]['processing'] = False
        bot.reply_to(message, "✅ Operation cancelled.\n\n🔄 Start again with /start.")
    else:
        bot.reply_to(message, "ℹ️ No active operation to cancel.\n\n🚀 Use /start to begin.")

# Webhook route
@app.route('/telegram', methods=['POST'])
def webhook():
    try:
        update = telebot.types.Update.de_json(request.get_json())
        bot.process_new_updates([update])
        return '', 200
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return '', 200

# Set webhook
def set_webhook():
    railway_domain = os.environ.get('RAILWAY_PUBLIC_DOMAIN')
    if not railway_domain:
        logger.error("RAILWAY_PUBLIC_DOMAIN not set")
        raise ValueError("RAILWAY_PUBLIC_DOMAIN not set")
    webhook_url = f"https://{railway_domain}/telegram"
    bot.set_webhook()
    time.sleep(1)
    bot.set_webhook(url=webhook_url)
    logger.info(f"Webhook set to: {webhook_url}")

if __name__ == "__main__":
    set_webhook()
    port = int(os.environ.get("PORT", 8000))
    logger.info(f"Starting Flask app on port {port}")
    app.run(host="0.0.0.0", port=port)