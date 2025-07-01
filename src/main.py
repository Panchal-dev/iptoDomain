import os
import sys
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.validator import IPValidator
from src.utils.console import IPLookupConsole
from src.utils.telegram import TelegramBot
from src.sources.sources import get_scrapers

class IPLookup:
    def __init__(self, bot_token, chat_id, output_file="domains.txt"):
        self.console = IPLookupConsole()
        self.bot = TelegramBot(bot_token, chat_id, self)
        self.output_file = output_file
        self.completed = 0
        self.ips = []

    def _fetch_from_source(self, source, ip):
        try:
            return source.fetch(ip)
        except Exception as e:
            self.console.print_error(f"Error in {source.name}: {str(e)}")
            return set()

    async def save_domains(self, domains, output_file):
        if domains:
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(domains)) + "\n")
            self.console.print(f"Results saved to {output_file}")
            await self.bot.send_file(output_file, domain_count=len(domains))
            try:
                os.remove(output_file)
                self.console.print(f"Deleted local file: {output_file}")
            except Exception as e:
                self.console.print_error(f"Error deleting file {output_file}: {str(e)}")
                await self.bot.send_message(f"Error deleting file {output_file}: {str(e)}")
        else:
            self.console.print_error("No domains found, no file saved.")
            await self.bot.send_message("No domains found, no file saved.")

    async def process_ip(self, ip, sources, total, cancel_event):
        if cancel_event.is_set():
            self.console.print(f"Scan cancelled for IP: {ip}")
            return set()

        if not IPValidator.is_valid_ip_or_cidr(ip):
            self.console.print_error(f"Invalid IP or CIDR: {ip}")
            await self.bot.send_message(f"Invalid IP or CIDR: {ip}")
            return set()

        self.console.print_ip_start(ip)
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(self._fetch_from_source, source, ip) for source in sources]
            results = [f.result() for f in as_completed(futures)]

        domains = set().union(*results) if results else set()
        self.console.update_ip_stats(ip, len(domains))
        self.console.print_ip_complete(ip, len(domains))

        return domains

    async def run_async(self, input_data, is_file=False, cancel_event=None, bot=None):
        sources = get_scrapers()
        self.ips = []

        if is_file:
            try:
                from .utils import process_file
                self.ips = process_file(input_data)
                self.output_file = "domains.txt"
            except Exception as e:
                self.console.print_error(f"Error reading file {input_data}: {str(e)}")
                await bot.send_message(f"Error reading input file: {str(e)}")
                return
        else:
            if isinstance(input_data, list):
                self.ips = [ip for ip in input_data if IPValidator.is_valid_ip_or_cidr(ip)]
                self.output_file = "domains.txt"
            else:
                from .utils import process_input
                self.ips = process_input(input_data)
                self.output_file = "domains.txt"
                if not self.ips:
                    self.console.print_error(f"Invalid input: {input_data}")
                    await bot.send_message(f"Invalid input: {input_data}")
                    return

        if not self.ips:
            self.console.print_error("No valid IPs provided")
            await bot.send_message("No valid IPs provided")
            return

        self.completed = 0
        total = len(self.ips)
        all_domains = set()

        if os.path.exists(self.output_file):
            try:
                os.remove(self.output_file)
            except Exception as e:
                self.console.print_error(f"Error clearing output file {self.output_file}: {str(e)}")
                await bot.send_message(f"Error clearing output file {self.output_file}: {str(e)}")

        max_concurrent = 3
        for i in range(0, len(self.ips), max_concurrent):
            if cancel_event and cancel_event.is_set():
                self.console.print("Scan cancelled")
                await bot.send_message("Scan cancelled")
                break
            batch = self.ips[i:i + max_concurrent]
            tasks = [self.process_ip(ip, sources, total, cancel_event) for ip in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            self.completed += len([r for r in results if isinstance(r, set)])
            await bot.update_progress(self.completed / total)
            for result in results:
                if isinstance(result, set):
                    all_domains.update(result)
                else:
                    self.console.print_error(f"Error processing IP: {str(result)}")
            self.console.print_progress(self.completed, total)

        if cancel_event and cancel_event.is_set():
            return

        await self.save_domains(all_domains, self.output_file)
        self.console.print_final_summary(self.output_file)

def main():
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    if not bot_token or not chat_id:
        print("Error: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set as environment variables")
        return

    iplookup = IPLookup(bot_token, chat_id)
    iplookup.bot.run()

if __name__ == "__main__":
    main()