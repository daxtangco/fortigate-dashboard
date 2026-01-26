import { Activity, Shield, ShieldOff, BarChart3, RotateCcw, Pause, Play, LogOut, ChevronDown } from 'lucide-react';
import { useState, useEffect } from 'react';
import useWebSocket from './hooks/useWebSocket';
import StatCard from './components/StatCard';
import LogTable from './components/LogTable';
import TopList from './components/TopList';
import ExpandableTopList from './components/ExpandableTopList';
import TrafficChart from './components/TrafficChart';
import Login from './components/Login';
import FirewallSelector from './components/FirewallSelector';
import { API_URL, WS_URL } from './config';
import './styles.css';

// Helper to get stored firewall from localStorage
const getStoredFirewall = () => {
  try {
    const stored = localStorage.getItem('selectedFirewall');
    return stored ? JSON.parse(stored) : null;
  } catch {
    return null;
  }
};

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [isAuthenticated, setIsAuthenticated] = useState(!!localStorage.getItem('token'));
  const [firewalls, setFirewalls] = useState([]);
  const [selectedFirewall, setSelectedFirewall] = useState(getStoredFirewall());
  const [loadingFirewalls, setLoadingFirewalls] = useState(false);
  const [authChecked, setAuthChecked] = useState(false);

  const { isConnected, isConnecting, logs, stats, trafficOverTime, topBlocked, topBlockedCategories, topBlockedDetail, topBlockedCategoriesDetail, clearLogs, pauseUpdates } = useWebSocket(
    isAuthenticated && selectedFirewall ? WS_URL : null,
    token,
    selectedFirewall?.id
  );
  const [isPaused, setIsPaused] = useState(false);

  // Verify token on mount
  useEffect(() => {
    if (token) {
      fetch(`${API_URL}/api/me`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
        .then(res => {
          if (res.ok) {
            setIsAuthenticated(true);
          } else {
            localStorage.removeItem('token');
            localStorage.removeItem('selectedFirewall');
            setToken(null);
            setIsAuthenticated(false);
            setSelectedFirewall(null);
          }
        })
        .catch(() => {
          localStorage.removeItem('token');
          localStorage.removeItem('selectedFirewall');
          setToken(null);
          setIsAuthenticated(false);
          setSelectedFirewall(null);
        })
        .finally(() => {
          setAuthChecked(true);
        });
    } else {
      setAuthChecked(true);
    }
  }, []);

  // Fetch firewalls when authenticated
  useEffect(() => {
    if (isAuthenticated && token) {
      setLoadingFirewalls(true);
      fetch(`${API_URL}/api/firewalls`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
        .then(res => res.json())
        .then(data => {
          setFirewalls(data);
          setLoadingFirewalls(false);
        })
        .catch(() => {
          setLoadingFirewalls(false);
        });
    }
  }, [isAuthenticated, token]);

  const handleLogin = (newToken) => {
    setToken(newToken);
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('selectedFirewall');
    setToken(null);
    setIsAuthenticated(false);
    setSelectedFirewall(null);
    setFirewalls([]);
  };

  const handleSelectFirewall = (fw) => {
    localStorage.setItem('selectedFirewall', JSON.stringify(fw));
    // Refresh page to ensure clean WebSocket connection
    window.location.reload();
  };

  const handleSwitchFirewall = () => {
    localStorage.removeItem('selectedFirewall');
    setSelectedFirewall(null);
    clearLogs();
  };

  const handlePause = () => {
    const newPausedState = !isPaused;
    setIsPaused(newPausedState);
    pauseUpdates(newPausedState);
  };

  const handleReset = async () => {
    if (!selectedFirewall) return;
    if (confirm('Are you sure you want to reset all statistics for this firewall?')) {
      try {
        await fetch(`${API_URL}/api/reset?fw=${selectedFirewall.id}`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        clearLogs();
      } catch {
        alert('Reset failed. Please try again.');
      }
    }
  };

  // Wait for auth check to complete before rendering
  if (!authChecked) {
    return (
      <div className="firewall-selector-container">
        <div className="firewall-selector-box">
          <div className="firewall-selector-header">
            <h1>Loading...</h1>
          </div>
        </div>
      </div>
    );
  }

  // Not authenticated → Show login
  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} />;
  }

  // Authenticated but no firewall selected → Show firewall selector
  if (!selectedFirewall) {
    return (
      <FirewallSelector
        firewalls={firewalls}
        onSelect={handleSelectFirewall}
        loading={loadingFirewalls}
      />
    );
  }

  // Authenticated and firewall selected → Show dashboard
  return (
    <div className="dashboard">
      <header className="header">
        <div className="header-left">
          <div className="header-firewall" onClick={handleSwitchFirewall} title="Click to switch firewall">
            <h1>{selectedFirewall.name}</h1>
            <ChevronDown size={20} className="header-firewall-icon" />
          </div>
          <div className={`status-badge ${isConnected ? 'connected' : isConnecting ? 'connecting' : 'disconnected'}`}>
            <span className="status-dot"></span>
            {isConnected ? 'Connected' : isConnecting ? 'Connecting...' : 'Disconnected'}
          </div>
        </div>
        <div className="header-actions">
          <button
            className="btn btn-secondary"
            onClick={handlePause}
          >
            {isPaused ? <Play size={16} /> : <Pause size={16} />}
            {isPaused ? 'Resume' : 'Pause'}
          </button>
          <button className="btn btn-danger" onClick={handleReset}>
            <RotateCcw size={16} />
            Reset
          </button>
          <button className="btn btn-secondary" onClick={handleLogout}>
            <LogOut size={16} />
            Logout
          </button>
        </div>
      </header>

      <div className="stats-grid">
        <StatCard
          title="Total Logs"
          value={stats.total_logs}
          icon={BarChart3}
        />
        <StatCard
          title="Allowed"
          value={stats.allowed_count}
          icon={Shield}
          color="text-green"
        />
        <StatCard
          title="Blocked"
          value={stats.blocked_count}
          icon={ShieldOff}
          color="text-red"
        />
        <StatCard
          title="Live Logs"
          value={logs.length}
          icon={Activity}
          color="text-blue"
        />
      </div>

      <div className="chart-section">
        <TrafficChart data={trafficOverTime} />
      </div>

      <div className="charts-grid">
        <TopList
          title="Top Source IPs"
          items={stats.top_sources || []}
          maxItems={5}
        />
        <TopList
          title="Top Destinations"
          items={stats.top_destinations || []}
          maxItems={5}
        />
        <ExpandableTopList
          title="Top Blocked Sites"
          items={topBlockedDetail || []}
          maxItems={5}
          labelKey="site"
        />
        <ExpandableTopList
          title="Top Blocked Categories"
          items={topBlockedCategoriesDetail || []}
          maxItems={5}
          labelKey="category"
        />
      </div>

      <LogTable logs={logs} />
    </div>
  );
}

export default App;
