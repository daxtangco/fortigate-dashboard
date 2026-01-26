# FortiGate Dashboard - Complete Setup Guide

This guide walks through setting up the FortiGate Syslog Dashboard from scratch.

---

## Prerequisites

- DigitalOcean account (or any Ubuntu server)
- Domain name (optional, for HTTPS)
- FortiGate firewall(s) with syslog capability
- Local development machine with Node.js and Python 3

---

## Part 1: Local Development Setup

### Step 1: Clone/Create Project Structure

```bash
mkdir fortigate-dashboard
cd fortigate-dashboard
mkdir -p backend/collectors frontend
```

### Step 2: Backend Setup

#### 2.1 Create Python Virtual Environment
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

#### 2.2 Install Dependencies
Create `backend/requirements.txt`:
```
fastapi==0.109.0
uvicorn==0.27.0
pydantic==2.5.3
pydantic-settings==2.1.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
websockets==12.0
asyncpg==0.29.0
```

Install:
```bash
pip install -r requirements.txt
```

#### 2.3 Create Configuration (`backend/config.py`)
```python
from functools import lru_cache
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    syslog_host: str = "0.0.0.0"
    syslog_port: int = 5514
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    debug: bool = True

    class Config:
        env_file = ".env"

@lru_cache
def get_settings():
    return Settings()
```

#### 2.4 Create Authentication (`backend/auth.py`)
```python
from datetime import datetime, timedelta
from typing import Optional
import hashlib

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from pydantic import BaseModel

SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

security = HTTPBearer()

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

# Hash: echo -n "admin-revlv" | sha256sum
USERS_DB = {
    "admin": {
        "username": "admin",
        "hashed_password": hashlib.sha256("admin-revlv".encode()).hexdigest(),
        "disabled": False,
    }
}

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password

def get_user(username: str) -> Optional[UserInDB]:
    if username in USERS_DB:
        return UserInDB(**USERS_DB[username])
    return None

def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user
```

#### 2.5 Create Syslog Collector (`backend/collectors/syslog_collector.py`)
```python
import asyncio
import re
from datetime import datetime
from typing import Callable
import logging

logger = logging.getLogger(__name__)


class FortiGateSyslogCollector:
    def __init__(self, host: str = "0.0.0.0", port: int = 5514):
        self.host = host
        self.port = port
        self._transport = None
        self._callbacks: list[Callable] = []
        self._running = False

    def on_log(self, callback: Callable):
        self._callbacks.append(callback)

    async def _notify(self, log_entry: dict):
        for cb in self._callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(log_entry)
                else:
                    cb(log_entry)
            except Exception as e:
                logger.error(f"Callback error: {e}")

    def parse_fortigate_log(self, raw: str) -> dict:
        pattern = r'(\w+)=(?:"([^"]*)"|([\S]+))'
        matches = re.findall(pattern, raw)

        parsed = {
            "raw": raw,
            "received_at": datetime.utcnow().isoformat(),
        }

        for key, quoted_val, unquoted_val in matches:
            value = quoted_val if quoted_val else unquoted_val
            if value.isdigit():
                value = int(value)
            parsed[key] = value

        if 'date' in parsed and 'time' in parsed:
            parsed['timestamp'] = f"{parsed['date']}T{parsed['time']}"

        parsed['log_category'] = self._categorize_log(parsed)
        return parsed

    def _categorize_log(self, log: dict) -> str:
        log_type = log.get('type', '')
        subtype = log.get('subtype', '')
        categories = {
            ('traffic', 'forward'): 'traffic_forward',
            ('traffic', 'local'): 'traffic_local',
            ('utm', 'virus'): 'security_av',
            ('utm', 'webfilter'): 'security_web',
            ('utm', 'ips'): 'security_ips',
            ('utm', 'app-ctrl'): 'security_app',
            ('event', 'system'): 'event_system',
            ('event', 'vpn'): 'event_vpn',
            ('event', 'user'): 'event_user',
        }
        return categories.get((log_type, subtype), f"{log_type}_{subtype}")

    class _SyslogProtocol(asyncio.DatagramProtocol):
        def __init__(self, collector):
            self.collector = collector

        def datagram_received(self, data: bytes, addr: tuple):
            try:
                raw = data.decode('utf-8', errors='replace').strip()
                if raw.startswith('<'):
                    idx = raw.find('>')
                    if idx > 0:
                        raw = raw[idx+1:].strip()
                log_entry = self.collector.parse_fortigate_log(raw)
                log_entry['source_ip'] = addr[0]
                asyncio.create_task(self.collector._notify(log_entry))
            except Exception as e:
                logger.error(f"Failed to parse syslog: {e}")

        def error_received(self, exc):
            logger.error(f"Syslog error: {exc}")

    async def start(self):
        loop = asyncio.get_event_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: self._SyslogProtocol(self),
            local_addr=(self.host, self.port)
        )
        self._running = True
        logger.info(f"Syslog receiver started on {self.host}:{self.port}")

    async def stop(self):
        if self._transport:
            self._transport.close()
        self._running = False
        logger.info("Syslog receiver stopped")


class LogAggregator:
    def __init__(self, max_logs: int = 1000):
        self.max_logs = max_logs
        self._logs: list = []
        self._lock = asyncio.Lock()
        self.stats = {
            'total_logs': 0,
            'by_action': {},
            'by_srcip': {},
            'by_dstip': {},
            'by_type': {},
            'blocked_count': 0,
            'allowed_count': 0,
            'blocked_sites': {},
            'by_destination': {},
            'blocked_categories': {},
            'blocked_sites_detail': {},
            'blocked_categories_detail': {},
        }

    def _is_ip_address(self, value: str) -> bool:
        if not value:
            return False
        parts = value.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False

    async def add_log(self, log: dict):
        async with self._lock:
            self._logs.append(log)
            if len(self._logs) > self.max_logs:
                self._logs = self._logs[-self.max_logs:]

            self.stats['total_logs'] += 1

            action = log.get('action', 'unknown')
            self.stats['by_action'][action] = self.stats['by_action'].get(action, 0) + 1

            action_lower = str(action).lower() if action else ''
            if action_lower in ('deny', 'denied', 'blocked', 'drop', 'block'):
                self.stats['blocked_count'] += 1
            elif action_lower in ('accept', 'accepted', 'allow', 'allowed', 'pass'):
                self.stats['allowed_count'] += 1

            srcip = log.get('srcip')
            if srcip:
                self.stats['by_srcip'][srcip] = self.stats['by_srcip'].get(srcip, 0) + 1

            dstip = log.get('dstip')
            if dstip:
                self.stats['by_dstip'][dstip] = self.stats['by_dstip'].get(dstip, 0) + 1

            hostname = log.get('hostname')
            if hostname and hostname != dstip and not self._is_ip_address(hostname):
                destination = hostname
            else:
                destination = dstip

            if destination:
                self.stats['by_destination'][destination] = self.stats['by_destination'].get(destination, 0) + 1

            log_type = log.get('type', '')
            subtype = log.get('subtype', '')

            if action_lower in ('deny', 'denied', 'blocked', 'drop', 'block') and log_type == 'utm':
                blocked_site = log.get('hostname') or log.get('dstip')
                if blocked_site and hostname and hostname != dstip and not self._is_ip_address(hostname):
                    blocked_site = hostname
                elif not blocked_site:
                    blocked_site = dstip

                if blocked_site:
                    self.stats['blocked_sites'][blocked_site] = self.stats['blocked_sites'].get(blocked_site, 0) + 1

                    if blocked_site not in self.stats['blocked_sites_detail']:
                        self.stats['blocked_sites_detail'][blocked_site] = {}
                    if srcip:
                        self.stats['blocked_sites_detail'][blocked_site][srcip] = \
                            self.stats['blocked_sites_detail'][blocked_site].get(srcip, 0) + 1

                catdesc = log.get('catdesc')
                if subtype == 'webfilter' or catdesc:
                    category = catdesc if catdesc else 'Other'
                    self.stats['blocked_categories'][category] = self.stats['blocked_categories'].get(category, 0) + 1

                    if category not in self.stats['blocked_categories_detail']:
                        self.stats['blocked_categories_detail'][category] = {}
                    if srcip:
                        if srcip not in self.stats['blocked_categories_detail'][category]:
                            self.stats['blocked_categories_detail'][category][srcip] = {}
                        if blocked_site:
                            self.stats['blocked_categories_detail'][category][srcip][blocked_site] = \
                                self.stats['blocked_categories_detail'][category][srcip].get(blocked_site, 0) + 1

            log_cat = log.get('log_category', 'unknown')
            self.stats['by_type'][log_cat] = self.stats['by_type'].get(log_cat, 0) + 1

    async def get_recent_logs(self, limit: int = 100) -> list:
        async with self._lock:
            return self._logs[-limit:]

    async def get_stats(self) -> dict:
        async with self._lock:
            top_sources = sorted(self.stats['by_srcip'].items(), key=lambda x: x[1], reverse=True)[:10]
            top_destinations = sorted(self.stats['by_destination'].items(), key=lambda x: x[1], reverse=True)[:10]
            top_blocked = sorted(self.stats['blocked_sites'].items(), key=lambda x: x[1], reverse=True)[:10]
            top_blocked_categories = sorted(self.stats['blocked_categories'].items(), key=lambda x: x[1], reverse=True)[:10]

            top_blocked_detail = []
            for site, count in top_blocked:
                sources = self.stats['blocked_sites_detail'].get(site, {})
                top_sources_for_site = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:10]
                top_blocked_detail.append({'site': site, 'count': count, 'sources': top_sources_for_site})

            top_blocked_categories_detail = []
            for category, count in top_blocked_categories:
                cat_data = self.stats['blocked_categories_detail'].get(category, {})
                flattened = []
                for srcip, destinations in cat_data.items():
                    for dest, dest_count in destinations.items():
                        flattened.append((srcip, dest, dest_count))
                top_sources_for_cat = sorted(flattened, key=lambda x: x[2], reverse=True)[:10]
                top_blocked_categories_detail.append({'category': category, 'count': count, 'sources': top_sources_for_cat})

            return {
                'total_logs': self.stats['total_logs'],
                'blocked_count': self.stats['blocked_count'],
                'allowed_count': self.stats['allowed_count'],
                'by_action': self.stats['by_action'],
                'by_type': self.stats['by_type'],
                'top_sources': top_sources,
                'top_destinations': top_destinations,
                'top_blocked': top_blocked,
                'top_blocked_categories': top_blocked_categories,
                'top_blocked_detail': top_blocked_detail,
                'top_blocked_categories_detail': top_blocked_categories_detail,
            }

    async def reset(self):
        async with self._lock:
            self._logs.clear()
            self.stats = {
                'total_logs': 0,
                'by_action': {},
                'by_srcip': {},
                'by_dstip': {},
                'by_type': {},
                'blocked_count': 0,
                'allowed_count': 0,
                'blocked_sites': {},
                'by_destination': {},
                'blocked_categories': {},
                'blocked_sites_detail': {},
                'blocked_categories_detail': {},
            }
```

#### 2.6 Create Main App (`backend/main.py`)
See the full `main.py` in the project - it includes:
- Multi-firewall configuration
- WebSocket handling per firewall
- Periodic stats broadcast
- All API endpoints with `?fw=` parameter

#### 2.7 Create Environment File (`backend/.env`)
```
SYSLOG_HOST=0.0.0.0
SYSLOG_PORT=5514
APP_HOST=0.0.0.0
APP_PORT=8000
DEBUG=true
```

### Step 3: Frontend Setup

#### 3.1 Initialize React Project
```bash
cd ../frontend
npm create vite@latest . -- --template react
npm install
```

#### 3.2 Install Dependencies
```bash
npm install recharts lucide-react
```

#### 3.3 Create Frontend Components
Copy all components from the project:
- `src/App.jsx`
- `src/hooks/useWebSocket.js`
- `src/components/Login.jsx`
- `src/components/FirewallSelector.jsx`
- `src/components/StatCard.jsx`
- `src/components/LogTable.jsx`
- `src/components/TopList.jsx`
- `src/components/ExpandableTopList.jsx`
- `src/components/TrafficChart.jsx`
- `src/styles.css`

#### 3.4 Update API URLs in `App.jsx`
```javascript
const WS_URL = 'wss://YOUR_SERVER_IP/ws';
const API_URL = 'https://YOUR_SERVER_IP';
```

#### 3.5 Build Frontend
```bash
npm run build
```

---

## Part 2: Server Setup (DigitalOcean)

### Step 4: Create Droplet

1. Log into DigitalOcean
2. Create Droplet:
   - **Image:** Ubuntu 24.04 LTS
   - **Plan:** Basic, 1GB RAM minimum (2GB recommended)
   - **Region:** Choose closest to your location
   - **Authentication:** SSH keys recommended
3. Note the IP address

### Step 5: Initial Server Setup

```bash
# SSH into server
ssh root@YOUR_SERVER_IP

# Update system
apt update && apt upgrade -y

# Install required packages
apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx

# Create application directory
mkdir -p /opt/fortigate-dashboard
mkdir -p /var/www/fortigate-dashboard
```

### Step 6: Deploy Backend

```bash
# On your local machine, upload backend
scp -r backend/* root@YOUR_SERVER_IP:/opt/fortigate-dashboard/backend/

# SSH into server
ssh root@YOUR_SERVER_IP

# Setup Python environment
cd /opt/fortigate-dashboard/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Test run
python main.py
# Press Ctrl+C to stop
```

### Step 7: Create Systemd Service

Create `/etc/systemd/system/fortigate-dashboard.service`:
```ini
[Unit]
Description=FortiGate Syslog Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/fortigate-dashboard/backend
Environment=PATH=/opt/fortigate-dashboard/backend/venv/bin
ExecStart=/opt/fortigate-dashboard/backend/venv/bin/python main.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
systemctl daemon-reload
systemctl enable fortigate-dashboard
systemctl start fortigate-dashboard
systemctl status fortigate-dashboard
```

### Step 8: Deploy Frontend

```bash
# On your local machine
scp -r frontend/dist/* root@YOUR_SERVER_IP:/var/www/fortigate-dashboard/
```

### Step 9: Configure Nginx

Create `/etc/nginx/sites-available/fortigate-dashboard`:
```nginx
server {
    listen 80;
    server_name YOUR_SERVER_IP;  # Or your domain name

    root /var/www/fortigate-dashboard;
    index index.html;

    # Frontend
    location / {
        try_files $uri $uri/ /index.html;
    }

    # API Proxy
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket Proxy
    location /ws {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }
}
```

Enable site:
```bash
ln -s /etc/nginx/sites-available/fortigate-dashboard /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default  # Remove default site
nginx -t  # Test configuration
systemctl restart nginx
```

### Step 10: Configure Firewall (UFW)

```bash
ufw allow 22/tcp      # SSH
ufw allow 80/tcp      # HTTP
ufw allow 443/tcp     # HTTPS
ufw allow 5514/udp    # Syslog for FortiGate 1
ufw allow 5515/udp    # Syslog for FortiGate 2
ufw enable
ufw status
```

### Step 11: Setup HTTPS (Optional but Recommended)

If you have a domain name:
```bash
certbot --nginx -d yourdomain.com
```

For IP-only access, you can use self-signed certificates or skip HTTPS.

---

## Part 3: FortiGate Configuration

### Step 12: Configure FortiGate Syslog

1. Log into FortiGate web interface
2. Go to **Log & Report → Log Settings**
3. Enable **Send Logs to Syslog**
4. Configure:
   - **IP Address:** Your server IP (e.g., 157.245.51.118)
   - **Port:** 5514 (or 5515 for second firewall)
   - **Server Type:** UDP
   - **Facility:** local7 (or any)
   - **Log Level:** Information (or as needed)

### Step 13: Verify Logs Arriving

```bash
# On server, check if logs are arriving
ssh root@YOUR_SERVER_IP
journalctl -u fortigate-dashboard -f

# You should see logs being received
```

---

## Part 4: Testing

### Step 14: Access Dashboard

1. Open browser: `http://YOUR_SERVER_IP`
2. Login with:
   - Username: `admin`
   - Password: `admin-revlv`
3. Select a firewall
4. Verify real-time logs are appearing

### Step 15: Verify Features

- [ ] Login works
- [ ] Firewall selection works
- [ ] Real-time logs appear
- [ ] Stats update every 5 seconds
- [ ] Blocked sites list populates (requires UTM blocks)
- [ ] Expandable lists work
- [ ] Page refresh maintains firewall selection
- [ ] Logout works

---

## Troubleshooting

### Backend not starting
```bash
journalctl -u fortigate-dashboard -n 100 --no-pager
```

### No logs appearing
1. Check FortiGate syslog settings
2. Verify UDP port is open: `ufw status`
3. Test with netcat: `nc -ul 5514`

### WebSocket not connecting
1. Check Nginx configuration
2. Verify backend is running: `systemctl status fortigate-dashboard`
3. Check browser console for errors

### Safari issues
- Safari has WebSocket quirks
- Current workaround: page reload on firewall selection
- Use Chrome/Brave for best experience

---

## Quick Reference

| Component | Location |
|-----------|----------|
| Backend code | `/opt/fortigate-dashboard/backend/` |
| Frontend files | `/var/www/fortigate-dashboard/` |
| Nginx config | `/etc/nginx/sites-available/fortigate-dashboard` |
| Systemd service | `/etc/systemd/system/fortigate-dashboard.service` |
| Backend logs | `journalctl -u fortigate-dashboard` |

| Port | Purpose |
|------|---------|
| 80 | HTTP (Nginx) |
| 443 | HTTPS (Nginx) |
| 8000 | Backend API (internal) |
| 5514 | Syslog UDP (FortiGate 1) |
| 5515 | Syslog UDP (FortiGate 2) |
