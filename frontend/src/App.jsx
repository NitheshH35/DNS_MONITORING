import React, { useEffect, useState } from 'react';
import StatusWidget from './components/StatusWidget';
import ClockWidget from './components/ClockWidget';

function App() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const response = await fetch('http://127.0.0.1:5000/logs');
        const data = await response.json();
        setLogs(data);
      } catch (error) {
        console.error('Error fetching logs:', error);
      }
    };
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app-container">
      <h1>
        <span className="h1-accent">DNS</span> Monitoring Dashboard
      </h1>

      <div className="dashboard-grid">
        <div className="grid-column-left">
          
          <StatusWidget logCount={logs.length} />
          
          <ClockWidget />
          
        </div>
        
        <div className="grid-column-right">
          <h2>Live DNS Query Logs</h2>
          <div className="widget-wrapper">
            <table className="dns-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Source IP</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {logs.length === 0 ? (
                  <tr>
                    <td colSpan="3" className="empty-logs-message">
                      No DNS logs yet...
                    </td>
                  </tr>
                ) : (
                  logs.map((log, index) => (
                    <tr key={index} className="log-row">
                      <td>{log.domain}</td>
                      <td>{log.src_ip}</td>
                      <td>{new Date(log.timestamp).toLocaleString()}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;