import asyncpg
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class Database:
    def __init__(self, host: str = "localhost", port: int = 5432,
                 user: str = "fortigate_user", password: str = "fortigate_pass123",
                 database: str = "fortigate_logs"):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self):
        """Create connection pool"""
        try:
            self.pool = await asyncpg.create_pool(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                min_size=2,
                max_size=10
            )
            logger.info("Database connection pool created")
            await self.create_tables()
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    async def create_tables(self):
        """Create necessary tables if they don't exist"""
        async with self.pool.acquire() as conn:
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP NOT NULL,
                    received_at TIMESTAMP NOT NULL,
                    source_ip VARCHAR(45),
                    srcip VARCHAR(45),
                    dstip VARCHAR(45),
                    hostname VARCHAR(255),
                    action VARCHAR(50),
                    type VARCHAR(50),
                    subtype VARCHAR(50),
                    log_category VARCHAR(50),
                    srcport INTEGER,
                    dstport INTEGER,
                    proto VARCHAR(10),
                    service VARCHAR(100),
                    app VARCHAR(100),
                    policyid INTEGER,
                    raw_log TEXT,
                    created_at TIMESTAMP DEFAULT NOW()
                )
            ''')

            # Create indexes for better query performance
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_logs_timestamp
                ON logs(timestamp DESC)
            ''')

            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_logs_action
                ON logs(action)
            ''')

            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_logs_srcip
                ON logs(srcip)
            ''')

            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_logs_dstip
                ON logs(dstip)
            ''')

            logger.info("Database tables created/verified")

    async def insert_log(self, log: Dict):
        """Insert a single log entry"""
        if not self.pool:
            return

        try:
            async with self.pool.acquire() as conn:
                # Parse timestamp
                timestamp_str = log.get('timestamp', datetime.utcnow().isoformat())
                if 'T' in timestamp_str:
                    timestamp = datetime.fromisoformat(timestamp_str)
                else:
                    timestamp = datetime.utcnow()

                # Convert proto to string if it's an integer
                proto = log.get('proto')
                if isinstance(proto, int):
                    proto = str(proto)

                await conn.execute('''
                    INSERT INTO logs (
                        timestamp, received_at, source_ip, srcip, dstip, hostname,
                        action, type, subtype, log_category, srcport, dstport,
                        proto, service, app, policyid, raw_log
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
                ''',
                    timestamp,
                    datetime.utcnow(),
                    log.get('source_ip'),
                    log.get('srcip'),
                    log.get('dstip'),
                    log.get('hostname'),
                    log.get('action'),
                    log.get('type'),
                    log.get('subtype'),
                    log.get('log_category'),
                    log.get('srcport'),
                    log.get('dstport'),
                    proto,
                    log.get('service'),
                    log.get('app'),
                    log.get('policyid'),
                    log.get('raw', '')
                )
        except Exception as e:
            logger.error(f"Failed to insert log: {e}")

    async def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        """Get most recent logs"""
        if not self.pool:
            return []

        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch('''
                    SELECT * FROM logs
                    ORDER BY timestamp DESC
                    LIMIT $1
                ''', limit)

                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to fetch logs: {e}")
            return []

    async def get_stats(self, hours: int = 24) -> Dict:
        """Get statistics for the last N hours"""
        if not self.pool:
            return {}

        try:
            async with self.pool.acquire() as conn:
                # Total logs
                total = await conn.fetchval('''
                    SELECT COUNT(*) FROM logs
                    WHERE timestamp > NOW() - INTERVAL '%s hours'
                ''', hours)

                # By action
                action_stats = await conn.fetch('''
                    SELECT action, COUNT(*) as count
                    FROM logs
                    WHERE timestamp > NOW() - INTERVAL '%s hours'
                    GROUP BY action
                ''', hours)

                # Top sources
                top_sources = await conn.fetch('''
                    SELECT srcip, COUNT(*) as count
                    FROM logs
                    WHERE timestamp > NOW() - INTERVAL '%s hours' AND srcip IS NOT NULL
                    GROUP BY srcip
                    ORDER BY count DESC
                    LIMIT 10
                ''', hours)

                # Top destinations
                top_dests = await conn.fetch('''
                    SELECT dstip, COUNT(*) as count
                    FROM logs
                    WHERE timestamp > NOW() - INTERVAL '%s hours' AND dstip IS NOT NULL
                    GROUP BY dstip
                    ORDER BY count DESC
                    LIMIT 10
                ''', hours)

                return {
                    'total_logs': total,
                    'by_action': {row['action']: row['count'] for row in action_stats},
                    'top_sources': [[row['srcip'], row['count']] for row in top_sources],
                    'top_destinations': [[row['dstip'], row['count']] for row in top_dests]
                }
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {}

    async def close(self):
        """Close database connection pool"""
        if self.pool:
            await self.pool.close()
            logger.info("Database connection pool closed")
