import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Dict, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm

from config import get_settings
from collectors.syslog_collector import FortiGateSyslogCollector, LogAggregator
from auth import (
    authenticate_user,
    create_access_token,
    get_current_active_user,
    Token,
    User,
    ACCESS_TOKEN_EXPIRE_MINUTES
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

settings = get_settings()

# ============================================================================
# FIREWALL CONFIGURATION
# ============================================================================
FIREWALLS = [
    {
        "id": "fg60f-30th",
        "name": "FortiGate-60F 30th",
        "port": 5514,
    },
    {
        "id": "fg60f-17th",
        "name": "FortiGate-60F 17th",
        "port": 5515,
    },
]

# Create a lookup dict for quick access
FIREWALL_MAP = {fw["id"]: fw for fw in FIREWALLS}


# ============================================================================
# APPLICATION STATE
# ============================================================================
class FirewallState:
    """State for a single firewall"""
    def __init__(self, firewall_id: str):
        self.firewall_id = firewall_id
        self.collector: FortiGateSyslogCollector = None
        self.aggregator: LogAggregator = None
        self.websocket_clients: Set[WebSocket] = set()


class AppState:
    """Global application state managing multiple firewalls"""
    def __init__(self):
        self.firewalls: Dict[str, FirewallState] = {}

    def get_firewall(self, firewall_id: str) -> FirewallState:
        if firewall_id not in self.firewalls:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Firewall '{firewall_id}' not found"
            )
        return self.firewalls[firewall_id]


state = AppState()


# ============================================================================
# BROADCAST FUNCTIONS
# ============================================================================
async def broadcast_to_firewall(firewall_id: str, message_type: str, data: dict):
    """Broadcast message to all clients connected to a specific firewall"""
    fw_state = state.firewalls.get(firewall_id)
    if not fw_state or not fw_state.websocket_clients:
        return

    message = json.dumps({
        "type": message_type,
        "data": data,
        "firewall_id": firewall_id,
        "timestamp": datetime.utcnow().isoformat()
    })

    disconnected = set()
    clients = list(fw_state.websocket_clients)
    for ws in clients:
        try:
            await ws.send_text(message)
        except Exception as e:
            logger.error(f"Broadcast error for {firewall_id}: {e}")
            disconnected.add(ws)

    fw_state.websocket_clients -= disconnected


def create_log_handler(firewall_id: str):
    """Create a log handler for a specific firewall"""
    async def on_log(log_entry: dict):
        fw_state = state.firewalls.get(firewall_id)
        if fw_state:
            await fw_state.aggregator.add_log(log_entry)
            await broadcast_to_firewall(firewall_id, "log", log_entry)
    return on_log


async def broadcast_stats_periodically():
    """Periodically broadcast updated stats to all clients for all firewalls"""
    while True:
        await asyncio.sleep(5)
        for firewall_id, fw_state in state.firewalls.items():
            if fw_state.websocket_clients:
                stats = await fw_state.aggregator.get_stats()
                await broadcast_to_firewall(firewall_id, "stats_update", {
                    "top_sources": stats.get("top_sources", []),
                    "top_destinations": stats.get("top_destinations", []),
                    "top_blocked": stats.get("top_blocked", []),
                    "top_blocked_categories": stats.get("top_blocked_categories", []),
                    "top_blocked_detail": stats.get("top_blocked_detail", []),
                    "top_blocked_categories_detail": stats.get("top_blocked_categories_detail", [])
                })


# ============================================================================
# LIFESPAN MANAGEMENT
# ============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 50)
    logger.info("Starting FortiGate Syslog Dashboard (Multi-Firewall)")
    logger.info("=" * 50)

    # Initialize each firewall
    for fw_config in FIREWALLS:
        fw_id = fw_config["id"]
        fw_name = fw_config["name"]
        fw_port = fw_config["port"]

        logger.info(f"Initializing {fw_name} (port {fw_port})...")

        fw_state = FirewallState(fw_id)
        fw_state.collector = FortiGateSyslogCollector(
            host=settings.syslog_host,
            port=fw_port
        )
        fw_state.aggregator = LogAggregator(max_logs=1000)

        # Register log handler for this firewall
        fw_state.collector.on_log(create_log_handler(fw_id))

        # Start the collector
        await fw_state.collector.start()

        state.firewalls[fw_id] = fw_state
        logger.info(f"  ✓ {fw_name} listening on port {fw_port}")

    # Start periodic stats broadcast
    stats_task = asyncio.create_task(broadcast_stats_periodically())

    logger.info("=" * 50)
    logger.info(f"Web server on http://{settings.app_host}:{settings.app_port}")
    logger.info(f"Firewalls configured: {len(FIREWALLS)}")
    logger.info("Dashboard ready!")
    logger.info("=" * 50)

    yield

    # Shutdown
    stats_task.cancel()
    try:
        await stats_task
    except asyncio.CancelledError:
        pass

    for fw_id, fw_state in state.firewalls.items():
        await fw_state.collector.stop()
        logger.info(f"Stopped collector for {fw_id}")

    logger.info("Shutdown complete")


# ============================================================================
# FASTAPI APP
# ============================================================================
app = FastAPI(title="FortiGate Syslog Dashboard", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# AUTH ENDPOINTS
# ============================================================================
@app.post("/api/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


# ============================================================================
# FIREWALL ENDPOINTS
# ============================================================================
@app.get("/api/firewalls")
async def get_firewalls(current_user: User = Depends(get_current_active_user)):
    """Get list of all configured firewalls"""
    return FIREWALLS


@app.get("/api/logs")
async def get_logs(
    fw: str = Query(..., description="Firewall ID"),
    limit: int = 100,
    current_user: User = Depends(get_current_active_user)
):
    """Get recent logs for a specific firewall"""
    fw_state = state.get_firewall(fw)
    return await fw_state.aggregator.get_recent_logs(limit)


@app.get("/api/stats")
async def get_stats(
    fw: str = Query(..., description="Firewall ID"),
    current_user: User = Depends(get_current_active_user)
):
    """Get stats for a specific firewall"""
    fw_state = state.get_firewall(fw)
    return await fw_state.aggregator.get_stats()


@app.post("/api/reset")
async def reset_stats(
    fw: str = Query(..., description="Firewall ID"),
    current_user: User = Depends(get_current_active_user)
):
    """Reset stats for a specific firewall"""
    fw_state = state.get_firewall(fw)
    await fw_state.aggregator.reset()
    return {"status": "ok", "firewall": fw}


@app.get("/api/debug/raw-logs")
async def get_raw_logs(
    fw: str = Query(..., description="Firewall ID"),
    limit: int = 10,
    current_user: User = Depends(get_current_active_user)
):
    """Debug endpoint to see raw log structure for a specific firewall"""
    fw_state = state.get_firewall(fw)
    logs = await fw_state.aggregator.get_recent_logs(limit)
    return {"firewall": fw, "logs": logs}


# ============================================================================
# WEBSOCKET ENDPOINT
# ============================================================================
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: str = None, fw: str = None):
    # Validate token
    if not token:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        from jose import jwt, JWTError
        from auth import SECRET_KEY, ALGORITHM
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            await ws.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except JWTError:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Validate firewall
    if not fw or fw not in FIREWALL_MAP:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    fw_state = state.firewalls.get(fw)
    if not fw_state:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws.accept()
    fw_state.websocket_clients.add(ws)
    logger.info(f"Client connected to {fw}. Total for {fw}: {len(fw_state.websocket_clients)}")

    try:
        # Send initial data
        stats = await fw_state.aggregator.get_stats()
        logs = await fw_state.aggregator.get_recent_logs(50)
        await ws.send_text(json.dumps({
            "type": "init",
            "data": {"stats": stats, "logs": logs},
            "firewall_id": fw,
            "timestamp": datetime.utcnow().isoformat()
        }))

        # Handle messages
        while True:
            try:
                data = await asyncio.wait_for(ws.receive_text(), timeout=30)
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                await ws.send_text(json.dumps({"type": "heartbeat"}))

    except WebSocketDisconnect:
        pass
    finally:
        fw_state.websocket_clients.discard(ws)
        logger.info(f"Client disconnected from {fw}. Total for {fw}: {len(fw_state.websocket_clients)}")


# ============================================================================
# HEALTH CHECK
# ============================================================================
@app.get("/")
async def home():
    return {
        "message": "FortiGate Syslog Dashboard API",
        "version": "2.0.0",
        "status": "running",
        "firewalls": len(FIREWALLS)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.app_host, port=settings.app_port, reload=settings.debug)
