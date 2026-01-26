import asyncio
from collectors.syslog_collector import FortiGateSyslogCollector, LogAggregator

async def test():
    print("=" * 50)
    print("Syslog Collector Test")
    print("=" * 50)
    
    collector = FortiGateSyslogCollector(host="0.0.0.0", port=5514)
    aggregator = LogAggregator(max_logs=100)
    
    def on_log(log):
        print(f"\nReceived log:")
        print(f"  Source IP: {log.get('srcip', 'N/A')}")
        print(f"  Dest IP:   {log.get('dstip', 'N/A')}")
        print(f"  Action:    {log.get('action', 'N/A')}")
        print(f"  Type:      {log.get('log_category', 'N/A')}")
    
    collector.on_log(on_log)
    collector.on_log(aggregator.add_log)
    
    await collector.start()
    
    print(f"\nListening on UDP port 5514...")
    print("Send a test log with this command (in another terminal):")
    print()
    print('  echo \'srcip=192.168.1.100 dstip=8.8.8.8 action="accept" type="traffic" subtype="forward"\' | nc -u localhost 5514')
    print()
    print("Press Ctrl+C to stop.\n")
    
    try:
        while True:
            await asyncio.sleep(5)
            stats = await aggregator.get_stats()
            if stats['total_logs'] > 0:
                print(f"[Stats] Total: {stats['total_logs']} | Allowed: {stats['allowed_count']} | Blocked: {stats['blocked_count']}")
    except KeyboardInterrupt:
        print("\nStopping...")
    
    await collector.stop()
    print("Done.")

if __name__ == "__main__":
    asyncio.run(test())
