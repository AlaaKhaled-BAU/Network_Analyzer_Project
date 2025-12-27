from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import json
import os
from dotenv import load_dotenv
from typing import List, Dict
import uvicorn

# Load environment variables
load_dotenv()

app = FastAPI(title="Telegram Bot Manager")

# Add CORS middleware to allow requests from NetGuardian dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Configuration ---
TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not TOKEN:
    raise Exception("TELEGRAM_BOT_TOKEN not found in .env file!")

URL_SEND = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
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
if os.path.exists(CHAT_IDS_FILE):
    with open(CHAT_IDS_FILE, "r") as f:
        registered_users = set(json.load(f))

def save_chat_ids():
    with open(CHAT_IDS_FILE, "w") as f:
        json.dump(list(registered_users), f)

def send_telegram_message(chat_id: int, text: str):
    try:
        response = requests.post(URL_SEND, data={"chat_id": chat_id, "text": text})
        return response.json()
    except Exception as e:
        print(f"Error sending message: {e}")
        return None

# --- API Endpoints ---

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serve the web dashboard"""
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
            <!-- Header -->
            <div class="bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg p-6 mb-8 shadow-xl">
                <h1 class="text-3xl font-bold flex items-center">
                    <i class="fab fa-telegram mr-3"></i>
                    Telegram Bot Manager
                </h1>
                <p class="text-blue-100 mt-2">Manage your bot, send broadcasts, and monitor messages</p>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <!-- Left Column: Controls -->
                <div class="lg:col-span-2 space-y-6">
                    
                    <!-- Webhook Setup Card -->
                    <div class="bg-gray-800 rounded-lg p-6 shadow-lg border border-gray-700">
                        <h2 class="text-xl font-semibold mb-4 flex items-center">
                            <i class="fas fa-link mr-2 text-blue-400"></i>
                            Webhook Setup
                        </h2>
                        <div class="space-y-3">
                            <input 
                                type="text" 
                                id="webhookUrl" 
                                placeholder="https://your-domain.com or ngrok URL"
                                class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-blue-500"
                            >
                            <button 
                                onclick="setWebhook()" 
                                class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-3 rounded-lg transition">
                                <i class="fas fa-check mr-2"></i>Set Webhook
                            </button>
                            <div id="webhookStatus" class="text-sm"></div>
                        </div>
                    </div>

                    <!-- Broadcast Message Card -->
                    <div class="bg-gray-800 rounded-lg p-6 shadow-lg border border-gray-700">
                        <h2 class="text-xl font-semibold mb-4 flex items-center">
                            <i class="fas fa-bullhorn mr-2 text-green-400"></i>
                            Broadcast Message
                        </h2>
                        <div class="space-y-3">
                            <textarea 
                                id="broadcastMessage" 
                                rows="4" 
                                placeholder="Type your message to send to all registered users..."
                                class="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 focus:outline-none focus:ring-2 focus:ring-green-500 resize-none"
                            ></textarea>
                            <div class="flex items-center justify-between">
                                <span id="userCount" class="text-sm text-gray-400">
                                    <i class="fas fa-users mr-1"></i>0 registered users
                                </span>
                                <button 
                                    onclick="sendBroadcast()" 
                                    class="bg-green-600 hover:bg-green-700 text-white font-medium px-6 py-3 rounded-lg transition">
                                    <i class="fas fa-paper-plane mr-2"></i>Send to All
                                </button>
                            </div>
                            <div id="broadcastStatus" class="text-sm"></div>
                        </div>
                    </div>

                    <!-- Activity Log Card -->
                    <div class="bg-gray-800 rounded-lg p-6 shadow-lg border border-gray-700">
                        <h2 class="text-xl font-semibold mb-4 flex items-center">
                            <i class="fas fa-list mr-2 text-yellow-400"></i>
                            Activity Log
                        </h2>
                        <div id="activityLog" class="bg-gray-900 rounded-lg p-4 h-64 overflow-y-auto text-sm font-mono">
                            <div class="text-gray-500">Waiting for activity...</div>
                        </div>
                    </div>
                </div>

                <!-- Right Column: Received Messages -->
                <div class="space-y-6">
                    <!-- Stats Card -->
                    <div class="bg-gradient-to-br from-purple-900 to-purple-800 rounded-lg p-6 shadow-lg">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-purple-200 text-sm">Total Users</p>
                                <p id="statsUsers" class="text-3xl font-bold mt-1">0</p>
                            </div>
                            <div class="bg-purple-500 p-3 rounded-lg">
                                <i class="fas fa-users text-2xl"></i>
                            </div>
                        </div>
                    </div>

                    <div class="bg-gradient-to-br from-blue-900 to-blue-800 rounded-lg p-6 shadow-lg">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-blue-200 text-sm">Messages Received</p>
                                <p id="statsMessages" class="text-3xl font-bold mt-1">0</p>
                            </div>
                            <div class="bg-blue-500 p-3 rounded-lg">
                                <i class="fas fa-envelope text-2xl"></i>
                            </div>
                        </div>
                    </div>

                    <!-- Received Messages -->
                    <div class="bg-gray-800 rounded-lg p-6 shadow-lg border border-gray-700">
                        <h2 class="text-xl font-semibold mb-4 flex items-center">
                            <i class="fas fa-inbox mr-2 text-purple-400"></i>
                            Received Messages
                        </h2>
                        <div id="receivedMessages" class="space-y-2 max-h-96 overflow-y-auto">
                            <div class="text-gray-500 text-sm text-center py-4">No messages yet</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            let activityLogElement = document.getElementById('activityLog');
            
            function addLog(message, type = 'info') {
                const colors = {
                    'info': 'text-blue-400',
                    'success': 'text-green-400',
                    'error': 'text-red-400',
                    'warning': 'text-yellow-400'
                };
                const time = new Date().toLocaleTimeString();
                const logEntry = document.createElement('div');
                logEntry.className = colors[type];
                logEntry.innerHTML = `<span class="text-gray-500">[${time}]</span> ${message}`;
                
                if (activityLogElement.firstChild.className === 'text-gray-500') {
                    activityLogElement.innerHTML = '';
                }
                activityLogElement.appendChild(logEntry);
                activityLogElement.scrollTop = activityLogElement.scrollHeight;
            }

            async function setWebhook() {
                const url = document.getElementById('webhookUrl').value;
                if (!url) {
                    alert('Please enter a webhook URL');
                    return;
                }
                
                addLog('Setting webhook...', 'info');
                try {
                    const response = await fetch('/api/webhook/set', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({webhook_url: url})
                    });
                    const data = await response.json();
                    
                    if (data.success) {
                        document.getElementById('webhookStatus').innerHTML = 
                            '<span class="text-green-400"><i class="fas fa-check-circle mr-1"></i>Webhook set successfully!</span>';
                        addLog('Webhook configured successfully', 'success');
                    } else {
                        document.getElementById('webhookStatus').innerHTML = 
                            '<span class="text-red-400"><i class="fas fa-times-circle mr-1"></i>Failed to set webhook</span>';
                        addLog('Webhook setup failed: ' + JSON.stringify(data), 'error');
                    }
                } catch (error) {
                    addLog('Error: ' + error.message, 'error');
                }
            }

            async function sendBroadcast() {
                const message = document.getElementById('broadcastMessage').value;
                if (!message) {
                    alert('Please enter a message');
                    return;
                }
                
                addLog('Sending broadcast message...', 'info');
                try {
                    const response = await fetch('/api/broadcast', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({message: message})
                    });
                    const data = await response.json();
                    
                    document.getElementById('broadcastStatus').innerHTML = 
                        `<span class="text-green-400"><i class="fas fa-check-circle mr-1"></i>Sent to ${data.sent_to} users</span>`;
                    addLog(`Broadcast sent to ${data.sent_to} users`, 'success');
                    document.getElementById('broadcastMessage').value = '';
                } catch (error) {
                    addLog('Error: ' + error.message, 'error');
                }
            }

            async function loadStats() {
                try {
                    const response = await fetch('/api/stats');
                    const data = await response.json();
                    
                    document.getElementById('userCount').innerHTML = 
                        `<i class="fas fa-users mr-1"></i>${data.total_users} registered users`;
                    document.getElementById('statsUsers').textContent = data.total_users;
                    document.getElementById('statsMessages').textContent = data.messages_received;
                } catch (error) {
                    console.error('Error loading stats:', error);
                }
            }

            async function loadMessages() {
                try {
                    const response = await fetch('/api/messages');
                    const data = await response.json();
                    
                    const container = document.getElementById('receivedMessages');
                    if (data.messages.length === 0) {
                        container.innerHTML = '<div class="text-gray-500 text-sm text-center py-4">No messages yet</div>';
                    } else {
                        container.innerHTML = data.messages.map(msg => `
                            <div class="bg-gray-700 rounded-lg p-3 border border-gray-600">
                                <div class="text-xs text-gray-400 mb-1">
                                    <i class="fas fa-user mr-1"></i>Chat ID: ${msg.chat_id}
                                </div>
                                <div class="text-sm">${msg.text}</div>
                                <div class="text-xs text-gray-500 mt-1">${msg.timestamp}</div>
                            </div>
                        `).join('');
                    }
                } catch (error) {
                    console.error('Error loading messages:', error);
                }
            }

            // Auto-refresh stats and messages
            setInterval(() => {
                loadStats();
                loadMessages();
            }, 3000);

            // Initial load
            loadStats();
            loadMessages();
            addLog('Bot manager initialized', 'success');
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
        
        # Keep only last 100 messages
        if len(received_messages) > 100:
            received_messages.pop(0)
        
        # Send auto-reply
        send_telegram_message(chat_id, "Hi! Thanks for your message.")
    
    return {"ok": True}

@app.post("/api/webhook/set")
async def set_webhook(webhook_setup: WebhookSetup):
    """Set the webhook URL"""
    full_url = f"{webhook_setup.webhook_url}/webhook/{TOKEN}"
    
    try:
        response = requests.get(
            f"https://api.telegram.org/bot{TOKEN}/setWebhook",
            params={"url": full_url}
        )
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
    """Get bot statistics"""
    return {
        "total_users": len(registered_users),
        "messages_received": len(received_messages)
    }

@app.get("/api/messages")
async def get_messages():
    """Get received messages"""
    formatted_messages = []
    for msg in reversed(received_messages[-50:]):  # Last 50 messages
        import datetime
        timestamp = datetime.datetime.fromtimestamp(msg["timestamp"]).strftime("%Y-%m-%d %H:%M:%S") if isinstance(msg["timestamp"], int) else "Unknown"
        formatted_messages.append({
            "chat_id": msg["chat_id"],
            "text": msg["text"],
            "timestamp": timestamp
        })
    
    return {"messages": formatted_messages}

if __name__ == "__main__":
    print("🚀 Starting Telegram Bot Manager...")
    print(f"📡 Webhook endpoint: http://localhost:5000/webhook/{TOKEN}")
    print(f"🌐 Dashboard: http://localhost:5000")
    uvicorn.run(app, host="0.0.0.0", port=5000)
