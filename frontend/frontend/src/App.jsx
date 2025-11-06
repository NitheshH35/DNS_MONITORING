import { useEffect, useState } from "react";

function App() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    fetch("http://127.0.0.1:5000/api/logs")
      .then((res) => res.json())
      .then((data) => setLogs(data))
      .catch((err) => console.error("Error fetching logs:", err));
  }, []);

  return (
    <div style={{ padding: "30px", fontFamily: "Arial" }}>
      <h1>🧠 DNS Monitoring Dashboard</h1>
      <p>Tracking real-time DNS queries from your network</p>

      <table border="1" cellPadding="10" style={{ marginTop: "20px", width: "100%", borderCollapse: "collapse" }}>
        <thead>
          <tr style={{ backgroundColor: "#f0f0f0" }}>
            <th>Domain</th>
            <th>Source IP</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {logs.length > 0 ? (
            logs.map((log, index) => (
              <tr key={index}>
                <td>{log.domain}</td>
                <td>{log.src_ip}</td>
                <td>{log.timestamp}</td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan="3">No DNS logs yet...</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default App;
