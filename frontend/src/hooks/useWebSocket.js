import { useState, useEffect, useRef, useCallback } from 'react';

const useWebSocket = (url, token, firewallId) => {
  const [isConnected, setIsConnected] = useState(false);
  const [isConnecting, setIsConnecting] = useState(false);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({
    total_logs: 0,
    allowed_count: 0,
    blocked_count: 0,
    by_action: {},
    by_type: {},
    top_sources: [],
    top_destinations: []
  });
  const [trafficOverTime, setTrafficOverTime] = useState([]);
  const [topBlocked, setTopBlocked] = useState([]);
  const [topBlockedCategories, setTopBlockedCategories] = useState([]);
  const [topBlockedDetail, setTopBlockedDetail] = useState([]);
  const [topBlockedCategoriesDetail, setTopBlockedCategoriesDetail] = useState([]);

  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const isPausedRef = useRef(false);
  const paramsRef = useRef({ url: null, token: null, firewallId: null });

  // Store latest params in ref to avoid stale closures
  paramsRef.current = { url, token, firewallId };

  const connect = useCallback(() => {
    const { url, token, firewallId } = paramsRef.current;

    if (!url || !token || !firewallId) {
      return;
    }

    // Don't connect if already connected or connecting
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    setIsConnecting(true);

    const wsUrl = `${url}?token=${encodeURIComponent(token)}&fw=${encodeURIComponent(firewallId)}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      setIsConnecting(false);
    };

    ws.onclose = (event) => {
      wsRef.current = null;
      setIsConnected(false);
      setIsConnecting(false);

      // Reconnect if not a clean close and params are still valid
      const { url, token, firewallId } = paramsRef.current;
      if (event.code !== 1000 && url && token && firewallId) {
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, 2000);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);

      if (msg.type === 'init') {
        setStats(msg.data.stats);
        const initialLogs = msg.data.logs || [];
        setLogs(initialLogs);

        setTopBlocked(msg.data.stats.top_blocked || []);
        setTopBlockedCategories(msg.data.stats.top_blocked_categories || []);
        setTopBlockedDetail(msg.data.stats.top_blocked_detail || []);
        setTopBlockedCategoriesDetail(msg.data.stats.top_blocked_categories_detail || []);

        // Build traffic over time from historical logs
        const trafficMap = {};
        initialLogs.forEach(log => {
          const logTime = log.timestamp ? new Date(log.timestamp) : new Date();
          const timeKey = `${logTime.getHours()}:${String(logTime.getMinutes()).padStart(2, '0')}`;
          const isBlocked = ['deny', 'block', 'drop', 'blocked'].includes(log.action);
          const isAllowed = ['accept', 'allow', 'pass', 'passthrough'].includes(log.action);

          if (!trafficMap[timeKey]) {
            trafficMap[timeKey] = { time: timeKey, allowed: 0, blocked: 0 };
          }
          if (isAllowed) trafficMap[timeKey].allowed++;
          if (isBlocked) trafficMap[timeKey].blocked++;
        });

        const trafficData = Object.values(trafficMap).sort((a, b) => {
          const [aH, aM] = a.time.split(':').map(Number);
          const [bH, bM] = b.time.split(':').map(Number);
          return (aH * 60 + aM) - (bH * 60 + bM);
        }).slice(-20);

        setTrafficOverTime(trafficData);
      }

      if (msg.type === 'log' && !isPausedRef.current) {
        const log = msg.data;
        const isBlocked = ['deny', 'block', 'drop', 'blocked'].includes(log.action);
        const isAllowed = ['accept', 'allow', 'pass', 'passthrough'].includes(log.action);

        setLogs(prev => [log, ...prev].slice(0, 1000));

        setStats(prev => ({
          ...prev,
          total_logs: prev.total_logs + 1,
          allowed_count: prev.allowed_count + (isAllowed ? 1 : 0),
          blocked_count: prev.blocked_count + (isBlocked ? 1 : 0)
        }));

        setTrafficOverTime(prev => {
          const logTime = log.timestamp ? new Date(log.timestamp) : new Date();
          const timeKey = `${logTime.getHours()}:${String(logTime.getMinutes()).padStart(2, '0')}`;
          const newData = [...prev];
          const lastEntry = newData[newData.length - 1];

          if (lastEntry && lastEntry.time === timeKey) {
            return [
              ...newData.slice(0, -1),
              {
                ...lastEntry,
                allowed: lastEntry.allowed + (isAllowed ? 1 : 0),
                blocked: lastEntry.blocked + (isBlocked ? 1 : 0),
                total: (lastEntry.total || 0) + 1
              }
            ];
          } else {
            return [...newData, { time: timeKey, allowed: isAllowed ? 1 : 0, blocked: isBlocked ? 1 : 0, total: 1 }].slice(-20);
          }
        });
      }

      if (msg.type === 'stats_update') {
        if (msg.data.top_sources || msg.data.top_destinations) {
          setStats(prev => ({
            ...prev,
            top_sources: msg.data.top_sources || prev.top_sources,
            top_destinations: msg.data.top_destinations || prev.top_destinations
          }));
        }
        if (msg.data.top_blocked) setTopBlocked(msg.data.top_blocked);
        if (msg.data.top_blocked_categories) setTopBlockedCategories(msg.data.top_blocked_categories);
        if (msg.data.top_blocked_detail) setTopBlockedDetail(msg.data.top_blocked_detail);
        if (msg.data.top_blocked_categories_detail) setTopBlockedCategoriesDetail(msg.data.top_blocked_categories_detail);
      }
    };
  }, []);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.onclose = null; // Prevent reconnect
      wsRef.current.close();
      wsRef.current = null;
    }
    setIsConnected(false);
    setIsConnecting(false);
  }, []);

  // Effect to manage connection based on params
  useEffect(() => {
    if (url && token && firewallId) {
      connect();
    } else {
      disconnect();
    }

    return () => {
      // Only disconnect on unmount if params become invalid
    };
  }, [url, token, firewallId, connect, disconnect]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      disconnect();
    };
  }, [disconnect]);

  const clearLogs = useCallback(() => {
    setLogs([]);
    setStats({
      total_logs: 0,
      allowed_count: 0,
      blocked_count: 0,
      by_action: {},
      by_type: {},
      top_sources: [],
      top_destinations: []
    });
    setTrafficOverTime([]);
    setTopBlocked([]);
    setTopBlockedCategories([]);
    setTopBlockedDetail([]);
    setTopBlockedCategoriesDetail([]);
  }, []);

  const pauseUpdates = useCallback((paused) => {
    isPausedRef.current = paused;
  }, []);

  return { isConnected, isConnecting, logs, stats, trafficOverTime, topBlocked, topBlockedCategories, topBlockedDetail, topBlockedCategoriesDetail, clearLogs, pauseUpdates };
};

export default useWebSocket;
