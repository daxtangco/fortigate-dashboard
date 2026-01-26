# FortiGate Dashboard - Development Session Notes

## Project Overview

**Location:** `/Users/daxtangco/Desktop/OJT/fortigate-dashboard/`

**Deployed Server:** `157.245.51.118` (DigitalOcean)

**Stack:**
- Backend: Python FastAPI
- Frontend: React + Vite
- Real-time: WebSocket
- Database: PostgreSQL (implemented but NOT active - using in-memory storage)

---

## Architecture

```
fortigate-dashboard/
├── backend/
│   ├── main.py                 # FastAPI app, multi-firewall support
│   ├── auth.py                 # JWT authentication
│   ├── config.py               # Pydantic settings
│   ├── database.py             # PostgreSQL (not used currently)
│   └── collectors/
│       └── syslog_collector.py # Syslog UDP receiver + LogAggregator
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Main app with firewall selection flow
│   │   ├── hooks/
│   │   │   └── useWebSocket.js # WebSocket connection management
│   │   └── components/
│   │       ├── FirewallSelector.jsx  # Firewall selection page
│   │       ├── ExpandableTopList.jsx # Expandable blocked sites/categories
│   │       ├── Login.jsx
│   │       ├── StatCard.jsx
│   │       ├── LogTable.jsx
│   │       ├── TopList.jsx
│   │       └── TrafficChart.jsx
│   └── dist/                   # Build output
└── .env                        # Environment config
```

---

## Deployment Details

### Server Setup
- **IP:** 157.245.51.118
- **Frontend:** Nginx serving `/var/www/fortigate-dashboard/` on port 80
- **Backend:** Systemd service `fortigate-dashboard` running on port 8000
- **Nginx proxies:** `/api/*` and `/ws` to backend

### URLs
- Frontend: `http://157.245.51.118` or `https://157.245.51.118`
- API: `https://157.245.51.118/api/*`
- WebSocket: `wss://157.245.51.118/ws`

### Deploy Commands
```bash
# Build frontend
cd /Users/daxtangco/Desktop/OJT/fortigate-dashboard/frontend
npm run build

# Upload backend
scp backend/main.py root@157.245.51.118:/opt/fortigate-dashboard/backend/
scp backend/collectors/syslog_collector.py root@157.245.51.118:/opt/fortigate-dashboard/backend/collectors/

# Upload frontend
scp -r frontend/dist/* root@157.245.51.118:/var/www/fortigate-dashboard/

# Restart backend
ssh root@157.245.51.118 "systemctl restart fortigate-dashboard"

# Check status
ssh root@157.245.51.118 "systemctl status fortigate-dashboard"
```

---

## Multi-Firewall Feature (Implemented)

### Configuration (in `main.py`)
```python
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
```

### User Flow
1. Login → Firewall Selection Page → Dashboard
2. Click firewall name in header → Returns to selection page
3. Selected firewall saved in localStorage (persists on refresh)
4. Selecting firewall triggers page reload (Safari WebSocket fix)

### API Endpoints (require `?fw=<firewall_id>`)
- `GET /api/firewalls` - List all firewalls
- `GET /api/stats?fw=fg60f-30th` - Stats for specific firewall
- `GET /api/logs?fw=fg60f-30th` - Logs for specific firewall
- `POST /api/reset?fw=fg60f-30th` - Reset stats
- `WS /ws?token=X&fw=fg60f-30th` - Real-time connection

---

## Blocked Sites/Categories Feature (Implemented)

### What it tracks
- **Blocked Sites:** Only UTM logs (`type=utm`) are tracked as blocked sites
  - Filters out inbound deny traffic (attackers blocked from YOUR network)
  - Only tracks outbound blocks (users blocked from accessing sites)

- **Blocked Categories:** Web filter categories with actual destination
  - Tracks: `{category: {srcip: {destination: count}}}`
  - Display shows: `192.168.10.2 → pokerstars.com (5)` not `192.168.10.2 → Gambling (5)`

### Expandable UI
- Click on blocked site/category → Expands to show source IPs
- `ExpandableTopList.jsx` component handles both formats

### Data Structures (in `syslog_collector.py`)
```python
stats = {
    'blocked_sites_detail': {site: {srcip: count}},
    'blocked_categories_detail': {category: {srcip: {destination: count}}},
}
```

---

## Known Issues

### 1. Source IP Shows Firewall IP (192.168.10.2)
- **Cause:** FortiGate NAT/routing configuration masks actual client IPs
- **Status:** Not fixable in dashboard - FortiGate config issue
- **Workaround:** None available unless FortiGate is reconfigured

### 2. Safari WebSocket Connection Issue
- **Symptom:** Gets stuck on "Connecting" when selecting firewall
- **Workaround Implemented:** Page reloads after firewall selection
- **Safari-specific fixes in code:**
  - Ping interval every 15 seconds
  - Visibility change handler for reconnection
  - Still has issues - refresh workaround is active

### 3. In-Memory Storage
- All logs/stats stored in RAM, lost on service restart
- Database layer exists but not activated
- Stats accumulate but memory usage is stable (~92MB)

---

## Current State

### Working
- ✅ Multi-firewall selection and switching
- ✅ Real-time log streaming via WebSocket
- ✅ Blocked sites tracking (UTM logs only)
- ✅ Blocked categories with actual destinations
- ✅ Expandable blocked lists showing source IPs
- ✅ Firewall selection persists on refresh
- ✅ Works in Chrome/Brave

### Needs Work
- ⚠️ Safari WebSocket issues (workaround: page reload)
- ⚠️ FortiGate-60F 17th not yet sending logs (port 5515 ready)
- ⚠️ Database persistence not enabled

---

## To Continue Development

### Adding More Firewalls
Edit `backend/main.py`:
```python
FIREWALLS = [
    {"id": "fg60f-30th", "name": "FortiGate-60F 30th", "port": 5514},
    {"id": "fg60f-17th", "name": "FortiGate-60F 17th", "port": 5515},
    {"id": "new-fw", "name": "New Firewall", "port": 5516},  # Add new
]
```
Then deploy and ensure UDP port is open on DigitalOcean firewall.

### Enable Database Persistence
1. Set up PostgreSQL on server
2. Update `database.py` with correct credentials
3. Modify `main.py` to use database instead of in-memory LogAggregator

### Debug Safari Issue
The Safari WebSocket issue happens during initial connection after firewall selection. Current workaround is page reload. For proper fix, need to investigate React state changes causing WebSocket disconnection.

---

## Authentication

- **Username:** admin
- **Password:** admin-revlv
- **JWT Expiry:** 8 hours
- **Secret Key:** Hardcoded in `auth.py` (should be moved to env)

---

## Useful Commands

```bash
# Check backend logs
ssh root@157.245.51.118 "journalctl -u fortigate-dashboard -n 50 --no-pager"

# Check memory usage
ssh root@157.245.51.118 "systemctl status fortigate-dashboard"

# Test API
ssh root@157.245.51.118 'curl -s http://localhost:8000/api/firewalls'

# Restart service
ssh root@157.245.51.118 "systemctl restart fortigate-dashboard"
```

---

## Session Date
**January 22, 2026**
