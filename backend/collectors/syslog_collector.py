import asyncio
import re
from datetime import datetime
from typing import Callable
import logging

logger = logging.getLogger(__name__)


class FortiGateSyslogCollector:
    """
    Receives syslog messages from FortiGate via UDP.
    
    FortiGate log format (key=value pairs):
    date=2024-01-15 time=10:30:45 devname="FG60F" type="traffic" 
    subtype="forward" srcip=192.168.1.100 dstip=8.8.8.8 action="accept" ...
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5514):
        self.host = host
        self.port = port
        self._transport = None
        self._callbacks: list[Callable] = []
        self._running = False
    
    def on_log(self, callback: Callable):
        """Register callback for when a log is received"""
        self._callbacks.append(callback)
    
    async def _notify(self, log_entry: dict):
        """Notify all callbacks of a new log"""
        for cb in self._callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(log_entry)
                else:
                    cb(log_entry)
            except Exception as e:
                logger.error(f"Callback error: {e}")
    
    def parse_fortigate_log(self, raw: str) -> dict:
        """
        Parse FortiGate key=value log format.
        
        Handles:
        - key=value
        - key="value with spaces"
        """
        # Regex: key=value or key="quoted value"
        pattern = r'(\w+)=(?:"([^"]*)"|([\S]+))'
        matches = re.findall(pattern, raw)
        
        parsed = {
            "raw": raw,
            "received_at": datetime.utcnow().isoformat(),
        }
        
        for key, quoted_val, unquoted_val in matches:
            value = quoted_val if quoted_val else unquoted_val
            
            # Convert to int if numeric
            if value.isdigit():
                value = int(value)
            
            parsed[key] = value
        
        # Create timestamp from date + time
        if 'date' in parsed and 'time' in parsed:
            parsed['timestamp'] = f"{parsed['date']}T{parsed['time']}"
        
        # Categorize log
        parsed['log_category'] = self._categorize_log(parsed)
        
        return parsed
    
    def _categorize_log(self, log: dict) -> str:
        """Categorize log by type and subtype"""
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
        """UDP protocol handler for syslog"""
        
        def __init__(self, collector):
            self.collector = collector
        
        def datagram_received(self, data: bytes, addr: tuple):
            """Called when a UDP packet arrives"""
            try:
                raw = data.decode('utf-8', errors='replace').strip()
                
                # Remove syslog header if present (e.g., <134>)
                if raw.startswith('<'):
                    idx = raw.find('>')
                    if idx > 0:
                        raw = raw[idx+1:].strip()
                
                # Parse the log
                log_entry = self.collector.parse_fortigate_log(raw)
                log_entry['source_ip'] = addr[0]
                
                # Notify callbacks
                asyncio.create_task(self.collector._notify(log_entry))
                
            except Exception as e:
                logger.error(f"Failed to parse syslog: {e}")
        
        def error_received(self, exc):
            logger.error(f"Syslog error: {exc}")
    
    async def start(self):
        """Start listening for syslog messages"""
        loop = asyncio.get_event_loop()
        
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: self._SyslogProtocol(self),
            local_addr=(self.host, self.port)
        )
        
        self._running = True
        logger.info(f"Syslog receiver started on {self.host}:{self.port}")
    
    async def stop(self):
        """Stop the syslog receiver"""
        if self._transport:
            self._transport.close()
        self._running = False
        logger.info("Syslog receiver stopped")


class LogAggregator:
    """
    Aggregates logs and calculates real-time statistics.

    Maintains:
    - Recent logs (last N logs)
    - Counts by action (allow/deny)
    - Top source IPs
    - Top destination IPs
    """

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
            'blocked_sites': {},  # Track blocked destinations
            'by_destination': {},  # Track all destinations (hostname preferred over IP)
            'blocked_categories': {},  # Track blocked web filter categories
            'blocked_sites_detail': {},  # Track source IPs per blocked site: {site: {srcip: count}}
            'blocked_categories_detail': {},  # Track source IPs per blocked category: {category: {srcip: count}}
        }

    def _is_ip_address(self, value: str) -> bool:
        """Check if a string is an IP address"""
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
        """Add a log entry and update statistics"""
        async with self._lock:
            # Store log
            self._logs.append(log)
            if len(self._logs) > self.max_logs:
                self._logs = self._logs[-self.max_logs:]
            
            # Update counters
            self.stats['total_logs'] += 1
            
            # By action
            action = log.get('action', 'unknown')
            self.stats['by_action'][action] = self.stats['by_action'].get(action, 0) + 1

            # Case-insensitive action matching
            action_lower = str(action).lower() if action else ''
            if action_lower in ('deny', 'denied', 'blocked', 'drop', 'block'):
                self.stats['blocked_count'] += 1
            elif action_lower in ('accept', 'accepted', 'allow', 'allowed', 'pass'):
                self.stats['allowed_count'] += 1
            
            # By source IP
            srcip = log.get('srcip')
            if srcip:
                self.stats['by_srcip'][srcip] = self.stats['by_srcip'].get(srcip, 0) + 1
            
            # By destination IP
            dstip = log.get('dstip')
            if dstip:
                self.stats['by_dstip'][dstip] = self.stats['by_dstip'].get(dstip, 0) + 1

            # Track all destinations (prefer hostname over IP if it's a real domain)
            hostname = log.get('hostname')
            # Use hostname if it exists and is not just an IP address
            if hostname and hostname != dstip and not self._is_ip_address(hostname):
                destination = hostname
            else:
                destination = dstip

            if destination:
                self.stats['by_destination'][destination] = self.stats['by_destination'].get(destination, 0) + 1

            # Track blocked sites - ONLY for UTM logs (webfilter, app-ctrl, virus, ips, etc.)
            # This filters out inbound deny/drop traffic and only tracks actual content blocks
            log_type = log.get('type', '')
            subtype = log.get('subtype', '')

            if action_lower in ('deny', 'denied', 'blocked', 'drop', 'block') and log_type == 'utm':
                blocked_site = log.get('hostname') or log.get('dstip')
                # Prefer hostname over IP if it's a real domain
                if blocked_site and hostname and hostname != dstip and not self._is_ip_address(hostname):
                    blocked_site = hostname
                elif not blocked_site:
                    blocked_site = dstip

                if blocked_site:
                    self.stats['blocked_sites'][blocked_site] = self.stats['blocked_sites'].get(blocked_site, 0) + 1

                    # Track source IP detail for this blocked site
                    if blocked_site not in self.stats['blocked_sites_detail']:
                        self.stats['blocked_sites_detail'][blocked_site] = {}
                    if srcip:
                        self.stats['blocked_sites_detail'][blocked_site][srcip] = \
                            self.stats['blocked_sites_detail'][blocked_site].get(srcip, 0) + 1

                # Track blocked categories from web filter only
                # Only count if it's a web filter log (has catdesc field or is subtype webfilter)
                catdesc = log.get('catdesc')

                if subtype == 'webfilter' or catdesc:
                    category = catdesc if catdesc else 'Other'
                    self.stats['blocked_categories'][category] = self.stats['blocked_categories'].get(category, 0) + 1

                    # Track source IP + destination detail for this blocked category
                    # Structure: {category: {srcip: {destination: count}}}
                    if category not in self.stats['blocked_categories_detail']:
                        self.stats['blocked_categories_detail'][category] = {}
                    if srcip:
                        if srcip not in self.stats['blocked_categories_detail'][category]:
                            self.stats['blocked_categories_detail'][category][srcip] = {}
                        # Use blocked_site as the destination (hostname preferred)
                        if blocked_site:
                            self.stats['blocked_categories_detail'][category][srcip][blocked_site] = \
                                self.stats['blocked_categories_detail'][category][srcip].get(blocked_site, 0) + 1

            # By type
            log_type = log.get('log_category', 'unknown')
            self.stats['by_type'][log_type] = self.stats['by_type'].get(log_type, 0) + 1
    
    async def get_recent_logs(self, limit: int = 100) -> list:
        """Get most recent logs"""
        async with self._lock:
            return self._logs[-limit:]
    
    async def get_stats(self) -> dict:
        """Get aggregated statistics"""
        async with self._lock:
            # Calculate top talkers
            top_sources = sorted(
                self.stats['by_srcip'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            # Use by_destination (hostname-preferred) instead of by_dstip for top destinations
            top_destinations = sorted(
                self.stats['by_destination'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]

            top_blocked = sorted(
                self.stats['blocked_sites'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]

            top_blocked_categories = sorted(
                self.stats['blocked_categories'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]

            # Build detailed blocked sites with source IPs (top 10 sources per site)
            top_blocked_detail = []
            for site, count in top_blocked:
                sources = self.stats['blocked_sites_detail'].get(site, {})
                top_sources_for_site = sorted(
                    sources.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10]
                top_blocked_detail.append({
                    'site': site,
                    'count': count,
                    'sources': top_sources_for_site  # List of [srcip, count]
                })

            # Build detailed blocked categories with source IPs and actual destinations
            # Structure: [(srcip, destination, count), ...]
            top_blocked_categories_detail = []
            for category, count in top_blocked_categories:
                cat_data = self.stats['blocked_categories_detail'].get(category, {})
                # Flatten {srcip: {dest: count}} into [(srcip, dest, count), ...]
                flattened = []
                for srcip, destinations in cat_data.items():
                    for dest, dest_count in destinations.items():
                        flattened.append((srcip, dest, dest_count))
                # Sort by count descending and take top 10
                top_sources_for_cat = sorted(
                    flattened,
                    key=lambda x: x[2],
                    reverse=True
                )[:10]
                top_blocked_categories_detail.append({
                    'category': category,
                    'count': count,
                    'sources': top_sources_for_cat  # List of (srcip, destination, count)
                })

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
        """Reset all statistics"""
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
