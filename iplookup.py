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
from flask import Flask, request
import logging
from datetime import datetime
import tempfile
import shutil
import re
from queue import Queue

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
REVIP_API_URL = "https://api.revip.workers.dev/"
NEW_REVIP_API_URL = "https://api.revip.workers.dev/"
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
ALLOWED_IDS = list(map(int, os.environ.get("ALLOWED_IDS", "").split(","))) if os.environ.get("ALLOWED_IDS") else []
PORT = int(os.environ.get("PORT", 8080))
GROUP_ID = -1002872150618  # Group ID
IPS_TOPIC_ID = 2  # Replace with actual "IPS" topic thread ID
IPS_OP_TOPIC_ID = 3  # Replace with actual "IPS OP" topic thread ID

# Flask app
app = Flask(__name__)
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

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

    def post(self, url, data=None, json=None, timeout=REQUEST_TIMEOUT):
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
        try:
            response = self.handler.get(f"https://rapiddns.io/sameip/{ip}")
            if response:
                soup = BeautifulSoup(response.content, 'html.parser')
                domains.update(self._extract_domains_from_page(soup))
                total_results = self._get_total_results(soup)
                if total_results > 100:
                    total_pages = math.ceil(total_results / 100)
                    for page in range(2, total_pages + 1):
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

# RevIP Source
class RevIPSource(DomainSource):
    def __init__(self, session):
        super().__init__("RevIP", session)

    def fetch(self, ip):
        domains = set()
        try:
            response = self.handler.post(REVIP_API_URL, json={"ips": [ip]})
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

# New RevIP API Source
class NewRevIPSource(DomainSource):
    def __init__(self, session):
        super().__init__("NewRevIP", session)

    def fetch(self, ip):
        domains = set()
        try:
            response = self.handler.post(
                NEW_REVIP_API_URL,
                headers={'Content-Type': 'application/json'},
                json={'ips': [ip]},
                timeout=REQUEST_TIMEOUT
            )
            if response:
                data = response.json()
                result = data.get(ip, {})
                if result.get('status') == 'success':
                    domains.update(result.get('domains', []))
                else:
                    logger.warning(f"NewRevIP API error for IP {ip}: {result.get('message', 'Unknown error')}")
        except requests.RequestException as e:
            logger.error(f"Error fetching from NewRevIP for IP {ip}: {e}")
        return domains

# Get scrapers
def get_scrapers(session):
    return [
        RapidDNSSource(session),
        YouGetSignalSource(session),
        RevIPSource(session),
        NewRevIPSource(session)
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
        pass  # Session will be passed per file

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

    def process_ip(self, ip, scrapers):
        try:
            with ThreadPoolExecutor(max_workers=len(scrapers)) as executor:
                futures = [
                    executor.submit(self._fetch_from_source, source, ip)
                    for source in scrapers
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

        # Create a new session for this file
        session = requests.Session()
        try:
            all_domains = set()
            scrapers = get_scrapers(session)
            with ThreadPoolExecutor(max_workers=2) as executor:  # Reduced for Railway
                futures = [executor.submit(self.process_ip, ip, scrapers) for ip in ips]
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
            return True, (output_files, len(all_domains))
        except Exception as e:
            logger.error(f"Error running IP lookup: {e}")
            return False, str(e)
        finally:
            # Close the session
            session.close()
            logger.info("Closed requests session for file processing")

# Processing queue
processing_queue = Queue()
processing_lock = Lock()
processing_active = False

# Process queue in background
def process_queue():
    global processing_active
    while True:
        if processing_queue.empty():
            time.sleep(1)
            continue

        with processing_lock:
            if processing_active:
                time.sleep(1)
                continue
            processing_active = True

        try:
            message = processing_queue.get()
            handle_file_message(message)
        except Exception as e:
            logger.error(f"Error processing queue item: {e}")
        finally:
            with processing_lock:
                processing_active = False
            processing_queue.task_done()

# Handle file message
def handle_file_message(message):
    chat_id = message.chat.id
    thread_id = message.message_thread_id
    file_name = message.document.file_name

    # Validate group and topic
    if chat_id != GROUP_ID or thread_id != IPS_TOPIC_ID:
        return

    # Validate file name
    match = re.match(r'ips_batch_(\d+)\.txt', file_name)
    if not match:
        bot.send_message(
            chat_id,
            f"❌ Invalid file name: {file_name}. Expected 'ips_batch_N.txt'.",
            message_thread_id=IPS_OP_TOPIC_ID
        )
        return

    batch_number = match.group(1)
    output_file_name = f"ips_op_{batch_number}.txt"

    try:
        # Notify processing start
        processing_message = bot.send_message(
            chat_id,
            f"⏳ Processing {file_name}...",
            message_thread_id=IPS_OP_TOPIC_ID
        )

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
            bot.edit_message_text(
                f"❌ No valid IPs or CIDRs found in {file_name}.",
                chat_id,
                processing_message.message_id,
                message_thread_id=IPS_OP_TOPIC_ID
            )
            os.unlink(temp_file_path)
            return

        # Run IP lookup
        output_dir = tempfile.mkdtemp()
        output_file = os.path.join(output_dir, output_file_name)
        iplookup = IPLookup()
        success, result = iplookup.run(ips, output_file)

        if not success:
            bot.edit_message_text(
                f"❌ Error processing {file_name}: {result}",
                chat_id,
                processing_message.message_id,
                message_thread_id=IPS_OP_TOPIC_ID
            )
            shutil.rmtree(output_dir, ignore_errors=True)
            os.unlink(temp_file_path)
            return

        # Send output files
        output_files, domain_count = result
        bot.edit_message_text(
            f"✅ Found {domain_count} domains for {file_name}!\n\n📤 Sending {output_file_name}...",
            chat_id,
            processing_message.message_id,
            message_thread_id=IPS_OP_TOPIC_ID
        )

        for output_file in output_files:
            with open(output_file, 'rb') as f:
                bot.send_document(
                    chat_id,
                    f,
                    filename=output_file_name,
                    message_thread_id=IPS_OP_TOPIC_ID,
                    caption=f"Domains found for {file_name} (one per line)."
                )

        # Cleanup
        shutil.rmtree(output_dir, ignore_errors=True)
        os.unlink(temp_file_path)

    except Exception as e:
        logger.error(f"Error processing {file_name}: {e}")
        bot.edit_message_text(
            f"❌ Failed to process {file_name}: {str(e)}",
            chat_id,
            processing_message.message_id,
            message_thread_id=IPS_OP_TOPIC_ID
        )
        if 'temp_file_path' in locals():
            try:
                os.unlink(temp_file_path)
            except:
                pass
        if 'output_dir' in locals():
            shutil.rmtree(output_dir, ignore_errors=True)

# Telegram bot handler for documents
@bot.message_handler(content_types=['document'])
def handle_document(message):
    if message.chat.id == GROUP_ID:
        processing_queue.put(message)
        logger.info(f"Added {message.document.file_name} to processing queue")

# Start queue processing thread
def start_queue_thread():
    from threading import Thread
    queue_thread = Thread(target=process_queue, daemon=True)
    queue_thread.start()
    logger.info("Started queue processing thread")

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

# Set webhook with retries
def set_webhook():
    railway_domain = os.getenv('RAILWAY_PUBLIC_DOMAIN')
    if not railway_domain:
        logger.error("RAILWAY_PUBLIC_DOMAIN not set")
        raise ValueError("RAILWAY_PUBLIC_DOMAIN not set")
    webhook_url = f"https://{railway_domain}/telegram"
    for attempt in range(3):
        try:
            bot.set_webhook(url=webhook_url)
            logger.info(f"Webhook set to: {webhook_url}")
            return
        except Exception as e:
            logger.error(f"Webhook attempt {attempt + 1} failed: {e}")
            time.sleep(2 ** attempt)
    logger.error("Failed to set webhook after 3 attempts")
    raise Exception("Webhook setup failed")

if __name__ == "__main__":
    try:
        set_webhook()
        start_queue_thread()
        logger.info(f"Starting Flask app on port {PORT}")
        app.run(host="0.0.0.0", port=PORT)
    except Exception as e:
        logger.error(f"Startup error: {e}")
        raise