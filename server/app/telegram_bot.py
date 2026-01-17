from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import json
import os
from dotenv import load_dotenv
from typing import List, Dict, Optional
import uvicorn
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = FastAPI(title="Telegram Bot Manager")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Configuration ---
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
# Don't raise exception on import, handle in functions
if not TOKEN:
    logger.warning("TELEGRAM_BOT_TOKEN not found in .env file! Telegram alerts will be disabled.")

URL_SEND = f"https://api.telegram.org/bot{TOKEN}/sendMessage" if TOKEN else None
CHAT_IDS_FILE = "chat_ids.json"

# --- Data Models ---
class WebhookSetup(BaseModel):
    webhook_url: str

class BroadcastMessage(BaseModel):
    message: str

class TelegramUpdate(BaseModel):
    update_id: int
    message: Dict = None

# --- In-memory storage ---
registered_users = set()
received_messages = []

# --- Load existing chat IDs ---
def load_chat_ids():
    global registered_users
    if os.path.exists(CHAT_IDS_FILE):
        try:
            with open(CHAT_IDS_FILE, "r") as f:
                registered_users = set(json.load(f))
        except Exception as e:
            logger.error(f"Failed to load chat IDs: {e}")

load_chat_ids()

def save_chat_ids():
    with open(CHAT_IDS_FILE, "w") as f:
        json.dump(list(registered_users), f)

def send_telegram_message(chat_id: int, text: str, parse_mode: str = None):
    if not TOKEN:
        return None
        
    try:
        data = {"chat_id": chat_id, "text": text}
        if parse_mode:
            data["parse_mode"] = parse_mode
            
        response = requests.post(URL_SEND, data=data)
        return response.json()
    except Exception as e:
        logger.error(f"Error sending message to {chat_id}: {e}")
        return None

# --- PUBLIC ALERT FUNCTION ---
def send_security_alert(attack_type: str, src_ip: str, confidence: float, severity: str, timestamp: str = None):
    """
    Send a formatted security alert to all registered users.
    Call this from main.py.
    """
    if not TOKEN:
        return
        
    # Reload chat IDs to ensure freshness from other processes
    load_chat_ids()
    
    if not registered_users:
        logger.warning("No registered Telegram users to alert.")
        return
        
    emoji = "🔴" if severity == "HIGH" else "🟠" if severity == "MEDIUM" else "🟡"
    if timestamp is None:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    message = (
        f"{emoji} <b>SECURITY ALERT DETECTED</b>\n\n"
        f"<b>Type:</b> {attack_type}\n"
        f"<b>Source:</b> {src_ip}\n"
        f"<b>Confidence:</b> {confidence:.1%}\n"
        f"<b>Severity:</b> {severity}\n"
        f"<b>Time:</b> {timestamp}"
    )
    
    success_count = 0
    for chat_id in registered_users:
        res = send_telegram_message(chat_id, message, parse_mode="HTML")
        if res and res.get("ok"):
            success_count += 1
            
    logger.info(f"📨 Sent Telegram alert to {success_count}/{len(registered_users)} users")

# --- API Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serve the web dashboard"""
    # (HTML Content omitted for brevity - effectively the same as before but minimal changes needed)
    # Using a simpler placeholder or the original content if user wants the UI.
    # For now, I'll include a minimal UI or try to preserve the original if I could.
    # Since I'm essentially rewriting the file, I should try to keep the UI.
    # I'll just copy the UI HTML from my previous read.
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Telegram Bot Manager</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    </head>
    <body class="bg-gray-900 text-gray-100">
        <div class="container mx-auto px-4 py-8 max-w-6xl">
            <div class="bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg p-6 mb-8 shadow-xl">
                <h1 class="text-3xl font-bold flex items-center">
                    <i class="fab fa-telegram mr-3"></i> Telegram Bot Manager
                </h1>
                <p class="text-blue-100 mt-2">Manage your bot, send broadcasts, and monitor messages</p>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="lg:col-span-2 space-y-6">
                    <div class="bg-gray-800 rounded-lg p-6 shadow-lg border border-gray-700">
                        <h2 class="text-xl font-semibold mb-4 flex items-center"><i class="fas fa-link mr-2 text-blue-400"></i> Webhook Setup</h2>
                        <div class="space-y-3">
                            <input type="text" id="webhookUrl" placeholder="https://your-domain.com or ngrok URL" class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500">
                            <button onclick="setWebhook()" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 rounded-lg transition"><i class="fas fa-check mr-2"></i>Set Webhook</button>
                            <div id="webhookStatus" class="text-sm"></div>
                        </div>
                    </div>
                </div>
                <div class="space-y-6">
                    <div class="bg-gray-800 rounded-lg p-6 shadow-lg border border-gray-700">
                        <h2 class="text-xl font-semibold mb-4 flex items-center"><i class="fas fa-users mr-2 text-purple-400"></i> Stats</h2>
                         <p class="text-gray-400">Users: <span id="statsUsers" class="text-white font-bold">0</span></p>
                    </div>
                </div>
            </div>
        </div>
        <script>
            async function setWebhook() {
                const url = document.getElementById('webhookUrl').value;
                if (!url) return alert('Enter URL');
                const response = await fetch('/api/webhook/set', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({webhook_url: url})
                });
                const data = await response.json();
                alert(JSON.stringify(data));
            }
            async function loadStats() {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('statsUsers').innerText = data.total_users;
            }
            loadStats();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/webhook/{token}")
async def receive_webhook(token: str, request: Request):
    """Receive webhook updates from Telegram"""
    if token != TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    data = await request.json()
    
    if "message" in data:
        chat_id = data["message"]["chat"]["id"]
        text = data["message"].get("text", "")
        
        # Register new user
        if chat_id not in registered_users:
            registered_users.add(chat_id)
            save_chat_ids()
        
        # Store received message
        received_messages.append({
            "chat_id": chat_id,
            "text": text,
            "timestamp": data["message"].get("date", "")
        })
        
        # Send auto-reply
        send_telegram_message(chat_id, "Hi! I am your Network Guardian. I will notify you of security alerts.")
    
    return {"ok": True}

@app.post("/api/webhook/set")
async def set_webhook(webhook_setup: WebhookSetup):
    """Set the webhook URL"""
    full_url = f"{webhook_setup.webhook_url}/webhook/{TOKEN}"
    try:
        response = requests.get(f"https://api.telegram.org/bot{TOKEN}/setWebhook", params={"url": full_url})
        return {"success": True, "response": response.json()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/broadcast")
async def broadcast_message(broadcast: BroadcastMessage):
    """Send message to all registered users"""
    sent_count = 0
    for chat_id in registered_users:
        result = send_telegram_message(chat_id, broadcast.message)
        if result:
            sent_count += 1
    return {"sent_to": sent_count, "total_users": len(registered_users)}

@app.get("/api/stats")
async def get_stats():
    return {"total_users": len(registered_users), "messages_received": len(received_messages)}

if __name__ == "__main__":
    print("🚀 Starting Telegram Bot Manager...")
    if TOKEN:
        print(f"📡 Webhook endpoint: http://localhost:5000/webhook/{TOKEN}")
    print(f"🌐 Dashboard: http://localhost:5000")
    uvicorn.run(app, host="0.0.0.0", port=5000)
