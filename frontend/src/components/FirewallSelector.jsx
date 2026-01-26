import { Shield } from 'lucide-react';

const FirewallSelector = ({ firewalls, onSelect, loading }) => {
  if (loading) {
    return (
      <div className="firewall-selector-container">
        <div className="firewall-selector-box">
          <div className="firewall-selector-header">
            <Shield size={48} className="firewall-icon" />
            <h1>FortiGate Dashboard</h1>
            <p>Loading firewalls...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="firewall-selector-container">
      <div className="firewall-selector-box">
        <div className="firewall-selector-header">
          <Shield size={48} className="firewall-icon" />
          <h1>FortiGate Dashboard</h1>
          <p>Select a firewall to monitor</p>
        </div>

        <div className="firewall-list">
          {firewalls.map((fw) => (
            <button
              key={fw.id}
              className="firewall-card"
              onClick={() => onSelect(fw)}
            >
              <div className="firewall-card-icon">
                <Shield size={24} />
              </div>
              <div className="firewall-card-info">
                <h3>{fw.name}</h3>
                <span className="firewall-card-port">Port {fw.port}</span>
              </div>
              <div className="firewall-card-arrow">→</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default FirewallSelector;
