import os
import time
import math
import random
import ipaddress
import requests
from bs4 import BeautifulSoup
import telebot
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from io import BytesIO
import threading

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Constants
TELEGRAM_BOT_TOKEN = "7687952078:AAEdXM7YwVAX48jGmdXQ8W85kKRAr6NtB38"
REQUEST_TIMEOUT = 10
MAX_RETRIES = 2
PROCESS_TIMEOUT = 300  # 5 minutes timeout for IP processing
HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
}
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
]

# Global variable to track processing status
processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}

# Request Handler
class RequestHandler:
    def __init__(self, session):
        self.session = session
        self.session.verify = False

    def _get_headers(self):
        headers = HEADERS.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)
        return headers

    def get(self, url, timeout=REQUEST_TIMEOUT):
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

# RapidDNS Source
class RapidDNSSource:
    def __init__(self, session):
        self.name = "RapidDNS"
        self.handler = RequestHandler(session)

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
            response = self.handler.get(f"https://rapiddns.io/sameip/{ip}")
            if response:
                soup = BeautifulSoup(response.content, 'html.parser')
                domains.update(self._extract_domains_from_page(soup))
                total_results = self._get_total_results(soup)
                if total_results > 100:
                    total_pages = math.ceil(total_results / 100)
                    for page in range(2, min(total_pages + 1, 3)):  # Limit to 2 pages for free tier
                        if processing_status["cancel_event"] and processing_status["cancel_event"].is_set():
                            logger.info("Processing cancelled for RapidDNS")
                            return domains
                        response = self.handler.get(f"https://rapiddns.io/sameip/{ip}?page={page}")
                        if response:
                            soup = BeautifulSoup(response.content, 'html.parser')
                            domains.update(self._extract_domains_from_page(soup))
        except Exception as e:
            logger.error(f"Error fetching from RapidDNS for IP {ip}: {e}")
        return domains

# Process IPs from file content or text
def process_input(input_data):
    ips = []
    try:
        lines = input_data.splitlines() if isinstance(input_data, str) else input_data.read().decode('utf-8').splitlines()
        for line in lines:
            line = line.strip()
            if line:
                try:
                    ipaddress.ip_address(line)
                    ips.append(line)
                except ValueError:
                    try:
                        network = ipaddress.ip_network(line, strict=False)
                        if network.num_addresses > 65536:  # Limit large CIDRs for free tier
                            logger.warning(f"CIDR {line} too large, skipping")
                            continue
                        ips.extend(str(ip) for ip in network.hosts())
                    except ValueError:
                        logger.warning(f"Invalid IP or CIDR: {line}")
        return list(set(ips))
    except Exception as e:
        logger.error(f"Error processing input: {e}")
        return []

# IP Lookup class
class IPLookup:
    def __init__(self):
        self.session = requests.Session()

    def _fetch_from_source(self, source, ip):
        try:
            domains = source.fetch(ip)
            logger.info(f"Fetched {len(domains)} domains from {source.name} for IP {ip}")
            return domains
        except Exception as e:
            logger.error(f"Error fetching from {source.name} for IP {ip}: {e}")
            return set()

    def _save_domains_to_buffer(self, domains):
        if domains:
            try:
                output = "\n".join(sorted(domains)) + "\n"
                return BytesIO(output.encode('utf-8'))
            except Exception as e:
                logger.error(f"Error creating output buffer: {e}")
                return None
        return None

    def process_ip(self, ip, source):
        try:
            domains = self._fetch_from_source(source, ip)
            return domains
        except Exception as e:
            logger.error(f"Error processing IP {ip}: {e}")
            return set()

    def run(self, ips):
        if not ips:
            return False, "No valid IPs provided", None

        try:
            all_domains = set()
            source = RapidDNSSource(self.session)
            start_time = time.time()

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(self.process_ip, ip, source) for ip in ips]
                for future in as_completed(futures, timeout=PROCESS_TIMEOUT):
                    if processing_status["cancel_event"] and processing_status["cancel_event"].is_set():
                        logger.info("Processing cancelled")
                        return False, "Processing cancelled by user", None
                    if time.time() - start_time > PROCESS_TIMEOUT:
                        logger.warning("Process timed out")
                        return False, "Processing timed out", None
                    try:
                        domains = future.result()
                        all_domains.update(domains)
                    except Exception as e:
                        logger.error(f"Error in IP processing thread: {e}")

            if not all_domains:
                return False, "No domains found for the provided IPs", None

            output_buffer = self._save_domains_to_buffer(all_domains)
            if not output_buffer:
                return False, "Failed to create output file", None

            return True, f"Found {len(all_domains)} domains", output_buffer
        except Exception as e:
            logger.error(f"Error running IP lookup: {e}")
            return False, str(e), None
        finally:
            self.session.close()
            logger.info("Closed requests session")

# Initialize bot
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# Delete webhook before starting polling
def delete_webhook():
    try:
        bot.delete_webhook()
        logger.info("Webhook deleted successfully")
    except Exception as e:
        logger.error(f"Failed to delete webhook: {e}")

# Command: Start
@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "👋 Welcome to the IP Lookup Bot! Send an IP, CIDR, or a .txt file with IPs (one per line) to get domains associated with them. Use /cmd for available commands.")

# Command: Commands list
@bot.message_handler(commands=['cmd'])
def send_commands(message):
    commands = (
        "/start - Start the bot\n"
        "/cmd - List all commands\n"
        "/status - Check if the bot is processing\n"
        "/cancel - Cancel the current processing task"
    )
    bot.reply_to(message, f"📜 Available commands:\n{commands}")

# Command: Status
@bot.message_handler(commands=['status'])
def check_status(message):
    if processing_status["is_running"]:
        bot.reply_to(message, "⏳ Bot is currently processing a task.")
    else:
        bot.reply_to(message, "✅ Bot is idle and ready to process your request.")

# Command: Cancel
@bot.message_handler(commands=['cancel'])
def cancel_processing(message):
    chat_id = message.chat.id
    if processing_status["is_running"] and processing_status["chat_id"] == chat_id:
        if processing_status["cancel_event"]:
            processing_status["cancel_event"].set()
            bot.reply_to(message, "🛑 Processing cancelled. Please wait a moment.")
        else:
            bot.reply_to(message, "❌ No processing task to cancel.")
    else:
        bot.reply_to(message, "❌ No active task for your chat to cancel.")

# Handle text messages (single IP or CIDR)
@bot.message_handler(content_types=['text'])
def handle_text(message):
    global processing_status
    chat_id = message.chat.id

    if processing_status["is_running"]:
        bot.reply_to(message, "⏳ Bot is busy with another task. Please wait or use /cancel to stop the current task.")
        return

    processing_status = {"is_running": True, "chat_id": chat_id, "cancel_event": threading.Event()}
    input_text = message.text.strip()

    try:
        try:
            ipaddress.ip_address(input_text)
            ips = [input_text]
        except ValueError:
            try:
                network = ipaddress.ip_network(input_text, strict=False)
                ips = [str(ip) for ip in network.hosts()]
            except ValueError:
                bot.reply_to(message, "❌ Invalid IP or CIDR format. Please provide a valid IP or CIDR.")
                processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}
                return
    except Exception as e:
        bot.reply_to(message, f"❌ Error validating input: {str(e)}")
        processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}
        return

    processing_message = bot.send_message(chat_id, "⏳ Processing your input...")
    iplookup = IPLookup()
    success, result_message, output_buffer = iplookup.run(ips)

    if processing_status["cancel_event"].is_set():
        bot.edit_message_text("🛑 Processing was cancelled.", chat_id, processing_message.message_id)
        processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}
        return

    if not success:
        bot.edit_message_text(result_message, chat_id, processing_message.message_id)
        processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}
        return

    bot.edit_message_text(result_message + "\n\n📤 Sending results...", chat_id, processing_message.message_id)
    output_buffer.seek(0)
    bot.send_document(
        chat_id,
        document=output_buffer,
        file_name="ip_lookup_results.txt",
        caption="Domains found (one per line)."
    )
    processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}

# Handle document messages (text file with IPs)
@bot.message_handler(content_types=['document'])
def handle_document(message):
    global processing_status
    chat_id = message.chat.id

    if processing_status["is_running"]:
        bot.reply_to(message, "⏳ Bot is busy with another task. Please wait or use /cancel to stop the current task.")
        return

    processing_status = {"is_running": True, "chat_id": chat_id, "cancel_event": threading.Event()}
    file_name = message.document.file_name

    if not file_name.endswith('.txt'):
        bot.reply_to(message, "❌ Please upload a .txt file containing IPs or CIDRs.")
        processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}
        return

    try:
        file_info = bot.get_file(message.document.file_id)
        file_url = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_info.file_path}"
        response = requests.get(file_url, timeout=10)
        response.raise_for_status()

        processing_message = bot.send_message(chat_id, f"⏳ Processing {file_name}...")
        ips = process_input(response.content)
        if not ips:
            bot.edit_message_text(f"❌ No valid IPs or CIDRs found in {file_name}.", chat_id, processing_message.message_id)
            processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}
            return

        iplookup = IPLookup()
        success, result_message, output_buffer = iplookup.run(ips)

        if processing_status["cancel_event"].is_set():
            bot.edit_message_text("🛑 Processing was cancelled.", chat_id, processing_message.message_id)
            processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}
            return

        if not success:
            bot.edit_message_text(result_message, chat_id, processing_message.message_id)
            processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}
            return

        bot.edit_message_text(result_message + f"\n\n📤 Sending results for {file_name}...", chat_id, processing_message.message_id)
        output_buffer.seek(0)
        bot.send_document(
            chat_id,
            document=output_buffer,
            file_name=f"ip_lookup_results_{file_name}",
            caption=f"Domains found for {file_name} (one per line)."
        )
        processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}

    except Exception as e:
        logger.error(f"Error processing {file_name}: {e}")
        bot.edit_message_text(f"❌ Failed to process {file_name}: {str(e)}", chat_id, processing_message.message_id)
        processing_status = {"is_running": False, "chat_id": None, "cancel_event": None}

if __name__ == "__main__":
    try:
        delete_webhook()
        logger.info("Starting bot polling...")
        bot.polling(none_stop=True, interval=0, timeout=20)
    except Exception as e:
        logger.error(f"Bot polling error: {e}")
        time.sleep(5)
        bot.polling(none_stop=True, interval=0, timeout=20)