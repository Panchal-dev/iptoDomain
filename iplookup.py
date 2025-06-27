import os
import time
import math
import random
import ipaddress
import requests
import telebot
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from io import BytesIO
import threading
import signal
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Constants
TELEGRAM_BOT_TOKEN = "7687952078:AAEdXM7YwVAX48jGmdXQ8W85kKRAr6NtB38"
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
PROCESS_TIMEOUT = 300  # 5 minutes timeout for IP processing

# Global variables for process control
current_process = None
process_lock = threading.Lock()
cancel_event = threading.Event()

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Request Handler
class RequestHandler:
    def __init__(self, session):
        self.session = session
        self.session.verify = False

    def _get_headers(self):
        headers = HEADERS.copy()
        headers["user-agent"] = random.choice(USER_AGENTS)
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

    def post(self, url, data=None, timeout=REQUEST_TIMEOUT):
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.session.post(url, data=data, timeout=timeout, headers=self._get_headers())
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                logger.warning(f"POST request failed for {url}: {e}. Attempt {attempt + 1}/{MAX_RETRIES + 1}")
                if attempt == MAX_RETRIES:
                    return None
                time.sleep(2 ** attempt)
        return None

# Domain Source base class
class DomainSource:
    def __init__(self, name, session):
        self.name = name
        self.handler = RequestHandler(session)

    def fetch(self, ip):
        raise NotImplementedError

# RapidDNS Source
class RapidDNSSource(DomainSource):
    def __init__(self, session):
        super().__init__("RapidDNS", session)

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
        if cancel_event.is_set():
            return domains
        try:
            response = self.handler.get(f"https://rapiddns.io/sameip/{ip}")
            if response:
                soup = BeautifulSoup(response.content, 'html.parser')
                domains.update(self._extract_domains_from_page(soup))
                total_results = self._get_total_results(soup)
                if total_results > 100:
                    total_pages = math.ceil(total_results / 100)
                    for page in range(2, min(total_pages + 1, 3)):  # Limit to 2 extra pages for free tier
                        if cancel_event.is_set():
                            break
                        response = self.handler.get(f"https://rapiddns.io/sameip/{ip}?page={page}")
                        if response:
                            soup = BeautifulSoup(response.content, 'html.parser')
                            domains.update(self._extract_domains_from_page(soup))
        except Exception as e:
            logger.error(f"Error fetching from RapidDNS for IP {ip}: {e}")
        return domains

# YouGetSignal Source
class YouGetSignalSource(DomainSource):
    def __init__(self, session):
        super().__init__("YouGetSignal", session)

    def fetch(self, ip):
        domains = set()
        if cancel_event.is_set():
            return domains
        try:
            data = {'remoteAddress': ip, 'key': '', '_': ''}
            response = self.handler.post("https://domains.yougetsignal.com/domains.php", data=data)
            if response and response.json().get("status") == "Success":
                domains.update(
                    domain[0] for domain in response.json().get("domainArray", [])
                    if domain and len(domain) > 0
                )
        except Exception as e:
            logger.error(f"Error fetching from YouGetSignal for IP {ip}: {e}")
        return domains

# Get scrapers
def get_scrapers(session):
    return [
        RapidDNSSource(session),
        YouGetSignalSource(session)
    ]

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
                        ips.extend(str(ip) for ip in network.hosts()[:100])  # Limit to 100 IPs for free tier
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

    def process_ip(self, ip, scrapers):
        if cancel_event.is_set():
            return set()
        try:
            with ThreadPoolExecutor(max_workers=len(scrapers)) as executor:
                futures = [
                    executor.submit(self._fetch_from_source, source, ip)
                    for source in scrapers
                ]
                results = []
                for future in as_completed(futures, timeout=PROCESS_TIMEOUT):
                    if cancel_event.is_set():
                        return set()
                    results.append(future.result())
            domains = set().union(*results) if results else set()
            logger.info(f"Processed IP {ip}: {len(domains)} domains found")
            return domains
        except Exception as e:
            logger.error(f"Error processing IP {ip}: {e}")
            return set()

    def run(self, ips):
        global current_process
        if not ips:
            return False, "No valid IPs provided", None

        try:
            all_domains = set()
            scrapers = get_scrapers(self.session)
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(self.process_ip, ip, scrapers) for ip in ips]
                for future in as_completed(futures, timeout=PROCESS_TIMEOUT):
                    if cancel_event.is_set():
                        return False, "Process cancelled", None
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

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    logger.info("Received shutdown signal, stopping bot...")
    bot.stop_polling()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Command handlers
@bot.message_handler(commands=['start'])
def send_welcome(message):
    bot.reply_to(message, "👋 Welcome to the IP Lookup Bot! Send an IP, CIDR, or a .txt file with IPs (one per line) to get domains associated with them. Use /cmd to see all commands.")

@bot.message_handler(commands=['cmd'])
def send_commands(message):
    commands = (
        "/start - Start the bot\n"
        "/cmd - List all commands\n"
        "/status - Check bot status\n"
        "/cancel - Cancel current processing"
    )
    bot.reply_to(message, f"📜 Available commands:\n{commands}")

@bot.message_handler(commands=['status'])
def send_status(message):
    global current_process
    with process_lock:
        if current_process and current_process.is_alive():
            bot.reply_to(message, "⏳ Bot is currently processing a request.")
        else:
            bot.reply_to(message, "✅ Bot is idle and ready to process requests.")

@bot.message_handler(commands=['cancel'])
def cancel_process(message):
    global current_process
    with process_lock:
        if current_process and current_process.is_alive():
            cancel_event.set()
            bot.reply_to(message, "🛑 Current process cancelled.")
        else:
            bot.reply_to(message, "ℹ️ No process is currently running.")

# Handle text messages (single IP or CIDR)
@bot.message_handler(content_types=['text'])
def handle_text(message):
    global current_process
    chat_id = message.chat.id
    input_text = message.text.strip()

    with process_lock:
        if current_process and current_process.is_alive():
            bot.reply_to(message, "⏳ Another process is running. Please wait or use /cancel to stop it.")
            return

    cancel_event.clear()  # Reset cancel event
    try:
        # Validate input
        try:
            ipaddress.ip_address(input_text)
            ips = [input_text]
        except ValueError:
            try:
                network = ipaddress.ip_network(input_text, strict=False)
                ips = [str(ip) for ip in network.hosts()[:100]]  # Limit to 100 IPs
            except ValueError:
                bot.reply_to(message, "❌ Invalid IP or CIDR format. Please provide a valid IP or CIDR.")
                return
    except Exception as e:
        bot.reply_to(message, f"❌ Error validating input: {str(e)}")
        return

    # Process IPs in a separate thread
    def process_task():
        processing_message = bot.send_message(chat_id, "⏳ Processing your input...")
        iplookup = IPLookup()
        success, result_message, output_buffer = iplookup.run(ips)

        if cancel_event.is_set():
            bot.edit_message_text("🛑 Process cancelled", chat_id, processing_message.message_id)
            return

        if not success:
            bot.edit_message_text(result_message, chat_id, processing_message.message_id)
            return

        # Send output file
        bot.edit_message_text(result_message + "\n\n📤 Sending results...", chat_id, processing_message.message_id)
        output_buffer.seek(0)
        bot.send_document(
            chat_id,
            document=output_buffer,
            file_name="ip_lookup_results.txt",
            caption="Domains found (one per line)."
        )

    with process_lock:
        current_process = threading.Thread(target=process_task)
        current_process.start()

# Handle document messages (text file with IPs)
@bot.message_handler(content_types=['document'])
def handle_document(message):
    global current_process
    chat_id = message.chat.id
    file_name = message.document.file_name

    with process_lock:
        if current_process and current_process.is_alive():
            bot.reply_to(message, "⏳ Another process is running. Please wait or use /cancel to stop it.")
            return

    if not file_name.endswith('.txt'):
        bot.reply_to(message, "❌ Please upload a .txt file containing IPs or CIDRs.")
        return

    cancel_event.clear()  # Reset cancel event
    try:
        # Download file
        file_info = bot.get_file(message.document.file_id)
        file_url = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_info.file_path}"
        response = requests.get(file_url, timeout=10)
        response.raise_for_status()

        # Process file content
        processing_message = bot.send_message(chat_id, f"⏳ Processing {file_name}...")
        ips = process_input(response.content)
        if not ips:
            bot.edit_message_text(f"❌ No valid IPs or CIDRs found in {file_name}.", chat_id, processing_message.message_id)
            return

        # Process IPs in a separate thread
        def process_task():
            iplookup = IPLookup()
            success, result_message, output_buffer = iplookup.run(ips)

            if cancel_event.is_set():
                bot.edit_message_text("🛑 Process cancelled", chat_id, processing_message.message_id)
                return

            if not success:
                bot.edit_message_text(result_message, chat_id, processing_message.message_id)
                return

            # Send output file
            bot.edit_message_text(result_message + f"\n\n📤 Sending results for {file_name}...", chat_id, processing_message.message_id)
            output_buffer.seek(0)
            bot.send_document(
                chat_id,
                document=output_buffer,
                file_name=f"ip_lookup_results_{file_name}",
                caption=f"Domains found for {file_name} (one per line)."
            )

        with process_lock:
            current_process = threading.Thread(target=process_task)
            current_process.start()

    except Exception as e:
        logger.error(f"Error processing {file_name}: {e}")
        bot.edit_message_text(f"❌ Failed to process {file_name}: {str(e)}", chat_id, processing_message.message_id)

# Delete webhook and start polling
def main():
    try:
        bot.delete_webhook()
        logger.info("Webhook deleted successfully")
        bot.infinity_polling(timeout=20, long_polling_timeout=20)
    except Exception as e:
        logger.error(f"Bot polling error: {e}")
        time.sleep(5)
        main()

if __name__ == "__main__":
    main()