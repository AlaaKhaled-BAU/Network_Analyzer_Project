import tkinter as tk
from tkinter import messagebox
import requests
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os

# --- Bot configuration ---
TOKEN = "8423302155:AAGUQx34_fPFWrYbrTaRCYIQFYydm8lmjlw"
URL_SEND = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
WEBHOOK_PORT = 5000  # Local server port
CHAT_IDS_FILE = "chat_ids.json"

# --- Load existing chat IDs ---
if os.path.exists(CHAT_IDS_FILE):
    with open(CHAT_IDS_FILE, "r") as f:
        registered_users = set(json.load(f))
else:
    registered_users = set()

# --- Function to save chat IDs ---
def save_chat_ids():
    with open(CHAT_IDS_FILE, "w") as f:
        json.dump(list(registered_users), f)

# --- HTTP Server to receive webhook ---
class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data)

        if "message" in data:
            chat_id = data["message"]["chat"]["id"]
            text = data["message"]["text"]
            # Register new user
            if chat_id not in registered_users:
                registered_users.add(chat_id)
                save_chat_ids()
            # Send "Hi" to the sender
            send_message(chat_id, "Hi")
            app.update_received_messages(f"{chat_id}: {text}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

def start_webhook_server():
    server = HTTPServer(('0.0.0.0', WEBHOOK_PORT), WebhookHandler)
    server.serve_forever()

# --- Telegram message sending ---
def send_message(chat_id, text):
    requests.post(URL_SEND, data={"chat_id": chat_id, "text": text})

# --- GUI ---
app = tk.Tk()
app.title("Telegram Bot GUI")
app.geometry("700x400")

# --- Layout ---
left_frame = tk.Frame(app)
left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

right_frame = tk.Frame(app, width=200)
right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)

# Left frame: Webhook and message sending
tk.Label(left_frame, text="Webhook URL (ngrok or public URL):").pack(pady=5)
webhook_entry = tk.Entry(left_frame, width=50)
webhook_entry.pack(pady=5)

def set_webhook():
    webhook_url = webhook_entry.get()
    if webhook_url:
        full_url = f"{webhook_url}/{TOKEN}"
        resp = requests.get(f"https://api.telegram.org/bot{TOKEN}/setWebhook?url={full_url}")
        messagebox.showinfo("Webhook", str(resp.json()))
    else:
        messagebox.showwarning("Error", "Enter webhook URL")

tk.Button(left_frame, text="Set Webhook", command=set_webhook).pack(pady=5)

tk.Label(left_frame, text="Send message to all registered users:").pack(pady=5)
message_entry = tk.Entry(left_frame, width=50)
message_entry.pack(pady=5)

def send_to_users():
    msg = message_entry.get()
    if msg:
        for user_id in registered_users:
            send_message(user_id, msg)
        update_chat(f"Sent '{msg}' to {len(registered_users)} users")
    else:
        messagebox.showwarning("Error", "Enter a message")

tk.Button(left_frame, text="Send Message", command=send_to_users).pack(pady=5)

chat_box = tk.Text(left_frame, height=15, width=60)
chat_box.pack(pady=5)

def update_chat(msg):
    chat_box.insert(tk.END, msg + "\n")
    chat_box.see(tk.END)

app.update_chat = update_chat

# Right frame: Sidebar for received messages
tk.Label(right_frame, text="Received Messages:").pack(pady=5)
received_box = tk.Listbox(right_frame, width=30)
received_box.pack(fill=tk.Y, expand=True)

def update_received_messages(msg):
    received_box.insert(tk.END, msg)
    received_box.see(tk.END)

app.update_received_messages = update_received_messages

# Start webhook server in background
threading.Thread(target=start_webhook_server, daemon=True).start()
update_chat("Webhook server running on port 5000...")

app.mainloop()
