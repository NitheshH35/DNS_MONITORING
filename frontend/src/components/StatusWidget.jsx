import React from 'react';

// This is the blinking dot component
const LiveIndicator = () => (
  <div className="live-indicator">
    <div className="blinking-dot"></div>
    <span>LIVE</span>
  </div>
);

function StatusWidget({ logCount }) {
  return (
    <div className="widget-wrapper">
      <h3 className="widget-title">System Status</h3>
      
      <div className="status-item">
        <span className="status-label">Service</span>
        <span className="status-value online">
          <LiveIndicator />
        </span>
      </div>
      
      <div className="status-item">
        <span className="status-label">Monitoring</span>
        <span className="status-value">Active</span>
      </div>
      
      <div className="status-item">
        <span className="status-label">Recent Logs</span>
        <span className="status-value">{logCount}</span>
      </div>
    </div>
  );
}

export default StatusWidget;