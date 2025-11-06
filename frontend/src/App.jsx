import React, { useEffect, useState } from "react";

function App() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const response = await fetch("http://127.0.0.1:5000/logs");
        const data = await response.json();
        setLogs(data);
      } catch (error) {
        console.error("Error fetching logs:", error);
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ padding: "20px", fontFamily: "Arial, sans-serif" }}>
      <h1>🧠 DNS Monitoring Dashboard</h1>
      <p>Live DNS Query Logs</p>

      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          marginTop: "20px",
          border: "1px solid #ddd",
        }}
      >
        <thead style={{ backgroundColor: "#f4f4f4" }}>
          <tr>
            <th style={{ border: "1px solid #ddd", padding: "10px" }}>Domain</th>
            <th style={{ border: "1px solid #ddd", padding: "10px" }}>Source IP</th>
            <th style={{ border: "1px solid #ddd", padding: "10px" }}>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {logs.length === 0 ? (
            <tr>
              <td colSpan="3" style={{ textAlign: "center", padding: "20px" }}>
                No DNS logs yet...
              </td>
            </tr>
          ) : (
            logs.map((log, index) => (
              <tr key={index}>
                <td style={{ border: "1px solid #ddd", padding: "10px" }}>{log.domain}</td>
                <td style={{ border: "1px solid #ddd", padding: "10px" }}>{log.src_ip}</td>
                <td style={{ border: "1px solid #ddd", padding: "10px" }}>{log.timestamp}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

export default App;
