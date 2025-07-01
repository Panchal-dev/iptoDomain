from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import os
import asyncio
import tempfile

class TelegramBot:
    def __init__(self, bot_token, chat_id, iplookup):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.iplookup = iplookup
        self.app = Application.builder().token(bot_token).build()
        self.is_running = False
        self.cancel_event = asyncio.Event()
        self.last_message_id = None
        self.progress_message_id = None

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "Welcome to the IP Lookup Bot! 🌐\n"
            "Send an IP, multiple IPs (one per line), a CIDR range, or upload a .txt file with IPs/CIDRs (one per line).\n"
            "Commands:\n"
            "/cmd - List all commands\n"
            "/status - Check scan status\n"
            "/cancel - Cancel current scan\n"
            "Example: 8.8.8.8\nor\n8.8.8.8\n192.168.1.0/24\nor upload ips.txt"
        )

    async def cmd(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "Available commands:\n"
            "/start - Show welcome message\n"
            "/cmd - List all commands\n"
            "/status - Check scan status\n"
            "/cancel - Cancel current scan\n"
            "Or send an IP, multiple IPs (one per line), a CIDR range, or upload a .txt file with IPs/CIDRs."
        )

    async def status(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        status = "Scanning in progress... Check the progress bar." if self.is_running else "No scan is currently running."
        await update.message.reply_text(status)

    async def cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != self.chat_id:
            await update.message.reply_text("Unauthorized chat ID.")
            return
        if self.is_running:
            self.cancel_event.set()
            await update.message.reply_text("Scan cancellation requested. Please wait...")
        else:
            await update.message.reply_text("No scan is currently running.")

    async def update_progress(self, progress):
        bar_length = 10
        filled = int(progress * bar_length)
        bar = '█' * filled + '□' * (bar_length - filled)
        percentage = int(progress * 100)
        message = f"Progress: [{bar}] {percentage}%"

        try:
            if self.progress_message_id:
                await self.app.bot.edit_message_text(
                    chat_id=self.chat_id,
                    message_id=self.progress_message_id,
                    text=message
                )
            else:
                sent_message = await self.app.bot.send_message(
                    chat_id=self.chat_id,
                    text=message
                )
                self.progress_message_id = sent_message.message_id

            print(f"Progress updated: {percentage}%")

            if percentage >= 100:
                await asyncio.sleep(1)
                await self.app.bot.delete_message(
                    chat_id=self.chat_id,
                    message_id=self.progress_message_id
                )
                self.progress_message_id = None
                print("Progress bar removed after completion.")

        except Exception as e:
            print(f"Error updating progress: {str(e)}")

    async def handle_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != self.chat_id:
            await update.message.reply_text("Unauthorized chat ID.")
            return

        message_id = update.message.message_id
        if message_id == self.last_message_id:
            return
        self.last_message_id = message_id

        if self.is_running:
            await update.message.reply_text("A scan is already in progress. Use /cancel to stop it or wait for it to complete.")
            return

        text = update.message.text.strip()
        if not text:
            await update.message.reply_text("Please provide an IP, multiple IPs (one per line), a CIDR range, or a .txt file path.")
            return

        self.cancel_event.clear()
        self.is_running = True
        self.progress_message_id = None

        try:
            if text.endswith('.txt') and os.path.isfile(text):
                from .http import process_file
                ips = process_file(text)
                if not ips:
                    await update.message.reply_text("No valid IPs found in the file.")
                    return
                await self.iplookup.run_async(ips, is_file=False, cancel_event=self.cancel_event, bot=self)
            else:
                from .http import process_input
                ips = []
                for line in text.split('\n'):
                    ips.extend(process_input(line.strip()))
                if not ips:
                    await update.message.reply_text("No valid input provided.")
                    return
                await self.iplookup.run_async(ips, is_file=False, cancel_event=self.cancel_event, bot=self)
        finally:
            self.is_running = False
            self.progress_message_id = None

    async def handle_document(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if str(update.effective_chat.id) != self.chat_id:
            await update.message.reply_text("Unauthorized chat ID.")
            return

        message_id = update.message.message_id
        if message_id == self.last_message_id:
            return
        self.last_message_id = message_id

        if self.is_running:
            await update.message.reply_text("A scan is already in progress. Use /cancel to stop it or wait for it to complete.")
            return

        document = update.message.document
        if not document or not document.file_name.endswith('.txt'):
            await update.message.reply_text("Please upload a .txt file with IPs/CIDRs (one per line).")
            return

        self.cancel_event.clear()
        self.is_running = True
        self.progress_message_id = None

        try:
            file = await context.bot.get_file(document.file_id)
            file_path = os.path.join(tempfile.gettempdir(), document.file_name)
            await file.download_to_drive(file_path)

            from .http import process_file
            ips = process_file(file_path)

            if not ips:
                await update.message.reply_text("No valid IPs found in the uploaded file.")
                return

            await self.iplookup.run_async(ips, is_file=False, cancel_event=self.cancel_event, bot=self)

            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Error deleting temporary file {file_path}: {str(e)}")
        except Exception as e:
            await update.message.reply_text(f"Error processing uploaded file: {str(e)}")
        finally:
            self.is_running = False
            self.progress_message_id = None

    async def send_message(self, message):
        try:
            await self.app.bot.send_message(chat_id=self.chat_id, text=message)
            print("Telegram notification sent successfully.")
        except Exception as e:
            print(f"Error sending Telegram notification: {str(e)}")

    async def send_file(self, file_path, domain_count=0):
        try:
            with open(file_path, 'rb') as file:
                caption = f"Found {domain_count} domains"
                await self.app.bot.send_document(
                    chat_id=self.chat_id,
                    document=file,
                    filename=os.path.basename(file_path),
                    caption=caption
                )
            print(f"Telegram file sent successfully: {file_path}")
        except Exception as e:
            print(f"Error sending Telegram file: {str(e)}")

    def run(self):
        self.app.add_handler(CommandHandler("start", self.start))
        self.app.add_handler(CommandHandler("cmd", self.cmd))
        self.app.add_handler(CommandHandler("status", self.status))
        self.app.add_handler(CommandHandler("cancel", self.cancel))
        self.app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text))
        self.app.add_handler(MessageHandler(filters.Document.TXT, self.handle_document))
        print("Bot is running...")
        self.app.run_polling(allowed_updates=Update.ALL_TYPES)
