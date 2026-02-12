import { useState } from 'react';
import { Search, Filter } from 'lucide-react';

const LogTable = ({ logs }) => {
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [viewLimit, setViewLimit] = useState(100);

  const matchedLogs = logs.filter(log => {
    // Filter by action
    if (filter === 'allow' && !['accept', 'allow', 'pass', 'passthrough'].includes(log.action)) {
      return false;
    }
    if (filter === 'block' && !['deny', 'block', 'drop', 'blocked'].includes(log.action)) {
      return false;
    }

    // Filter by search
    if (search) {
      const searchLower = search.toLowerCase();
      const srcip = (log.srcip || '').toLowerCase();
      const dstip = (log.dstip || '').toLowerCase();
      const hostname = (log.hostname || '').toLowerCase();
      const url = (log.url || '').toLowerCase();

      if (!srcip.includes(searchLower) &&
          !dstip.includes(searchLower) &&
          !hostname.includes(searchLower) &&
          !url.includes(searchLower)) {
        return false;
      }
    }

    return true;
  });

  const filteredLogs = matchedLogs.slice(0, viewLimit);

  const getActionClass = (action) => {
    if (['accept', 'allow', 'pass', 'passthrough'].includes(action)) {
      return 'action-allow';
    }
    if (['deny', 'block', 'drop', 'blocked'].includes(action)) {
      return 'action-block';
    }
    return '';
  };

  const formatTime = (log) => {
    if (log.timestamp) {
      return log.timestamp.split('T')[1] || log.timestamp;
    }
    if (log.received_at) {
      return new Date(log.received_at).toLocaleTimeString();
    }
    return '-';
  };

  return (
    <div className="log-table-container">
      <div className="log-table-header">
        <h2>Live Logs</h2>
        <div className="log-filters">
          <div className="filter-group">
            <Filter size={16} />
            <select value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="all">All Actions</option>
              <option value="allow">Allowed</option>
              <option value="block">Blocked</option>
            </select>
          </div>
          <div className="filter-group">
            <select value={viewLimit} onChange={(e) => setViewLimit(Number(e.target.value))}>
              <option value={50}>Show 50</option>
              <option value={100}>Show 100</option>
              <option value={200}>Show 200</option>
              <option value={300}>Show 300</option>
              <option value={500}>Show 500</option>
              <option value={1000}>Show All (1000)</option>
            </select>
          </div>
          <div className="search-group">
            <Search size={16} />
            <input
              type="text"
              placeholder="Search IP or hostname..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
      </div>

      <div className="log-table-wrapper">
        <table className="log-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source IP</th>
              <th>Destination</th>
              <th>Port</th>
              <th>Action</th>
              <th>Type</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan="6" className="no-logs">
                  {logs.length === 0 ? 'Waiting for logs...' : 'No matching logs'}
                </td>
              </tr>
            ) : (
              filteredLogs.map((log, index) => (
                <tr key={index} className={getActionClass(log.action)}>
                  <td className="col-time">{formatTime(log)}</td>
                  <td className="col-ip">{log.srcip || '-'}</td>
                  <td className="col-dest">{log.hostname || log.dstip || '-'}</td>
                  <td className="col-port">{log.dstport || '-'}</td>
                  <td className="col-action">
                    <span className={`action-badge ${getActionClass(log.action)}`}>
                      {log.action || '-'}
                    </span>
                  </td>
                  <td className="col-type">{log.log_category || log.type || '-'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      
      <div className="log-table-footer">
        Showing {filteredLogs.length} of {matchedLogs.length} matched ({logs.length} total in memory)
      </div>
    </div>
  );
};

export default LogTable;
