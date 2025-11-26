import { useEffect, useMemo, useState } from "react";
import io from "socket.io-client";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  LineChart,
  Line,
  CartesianGrid,
  Legend,
} from "recharts";

const API = "http://127.0.0.1:5000";

export default function App() {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({
    topDomains: [],
    topIPs: [],
    perMinute: [],
  });
  const [alerts, setAlerts] = useState([]);
  const [dark, setDark] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  // initial fetch + polling (backup if websocket disconnects)
  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [l, s, a] = await Promise.all([
          fetch(`${API}/logs`).then((r) => r.json()),
          fetch(`${API}/stats`).then((r) => r.json()),
          fetch(`${API}/alerts`).then((r) => r.json()),
        ]);
        setLogs(l || []);
        setStats(s || { topDomains: [], topIPs: [], perMinute: [] });
        setAlerts(a?.alerts || []);
        setLastUpdated(new Date());
      } catch (err) {
        console.error("Fetch error:", err);
      }
    };
    fetchAll();
    const t = setInterval(fetchAll, 5000);
    return () => clearInterval(t);
  }, []);

  // WebSocket: push new logs live
  useEffect(() => {
    const socket = io(API, { transports: ["websocket"] });

    socket.on("connect", () => {
      console.log("WS connected");
      setWsConnected(true);
    });

    socket.on("disconnect", () => {
      console.log("WS disconnected");
      setWsConnected(false);
    });

    socket.on("new_log", (msg) => {
      setLogs((prev) => [msg, ...prev].slice(0, 500));
      setLastUpdated(new Date());
    });

    return () => socket.close();
  }, []);

  const exportCsv = () => {
    window.location.href = `${API}/export/csv`;
  };

  const suspiciousCount = useMemo(
    () => alerts.filter((a) => a.type === "SuspiciousDomain").length,
    [alerts]
  );

  const uniqueDomains = useMemo(
    () => new Set(logs.map((l) => l.domain)).size,
    [logs]
  );

  const uniqueIPs = useMemo(
    () => new Set(logs.map((l) => l.src_ip)).size,
    [logs]
  );

  // Clock for the side widget
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const timeString = now
    .toLocaleTimeString("en-IN", { hour12: false })
    .split(":");
  const dateString = now.toLocaleString("en-IN", {
    weekday: "short",
    day: "2-digit",
    month: "short",
    year: "numeric",
  });

  return (
    <div className={`app-container ${dark ? "" : "theme-light"}`}>
      {/* HEADER */}
      <header className="app-header">
        <div className="app-title-block">
          <h1>
            <span className="h1-accent">DNS</span> Monitoring Console
          </h1>
          <div className="subtitle">
            Real-time visibility into DNS queries on your network
          </div>
        </div>

        <div className="app-header-right">
          <div className="live-indicator">
            <span className="blinking-dot" />
            <span>{wsConnected ? "LIVE FEED" : "STANDBY"}</span>
          </div>

          <button className="btn-ghost" onClick={exportCsv}>
            ⬇ Export CSV
          </button>

          <button
            className="btn-toggle"
            onClick={() => setDark((prev) => !prev)}
          >
            {dark ? "☀ Light Theme" : "🌙 Dark Theme"}
          </button>
        </div>
      </header>

      {/* MAIN GRID */}
      <div className="dashboard-grid">
        {/* LEFT SIDEBAR */}
        <aside className="sidebar-column">
          {/* STATUS WIDGET */}
          <div className="widget-wrapper">
            <h3 className="widget-title">System Status</h3>
            <div className="status-item">
              <span className="status-label">Backend API</span>
              <span className="status-value online">ONLINE</span>
            </div>
            <div className="status-item">
              <span className="status-label">WebSocket</span>
              <span
                className={`status-value ${
                  wsConnected ? "online" : ""
                }`.trim()}
              >
                {wsConnected ? "CONNECTED" : "DISCONNECTED"}
              </span>
            </div>
            <div className="status-item">
              <span className="status-label">Total Logs in View</span>
              <span className="status-value">{logs.length}</span>
            </div>
            <div className="status-item">
              <span className="status-label">Unique Domains</span>
              <span className="status-value">{uniqueDomains}</span>
            </div>
            <div className="status-item">
              <span className="status-label">Unique Source IPs</span>
              <span className="status-value">{uniqueIPs}</span>
            </div>
            <div className="status-item">
              <span className="status-label">Suspicious Alerts</span>
              <span
                className="status-value"
                style={{
                  color: suspiciousCount ? "#ff4b4b" : undefined,
                }}
              >
                {suspiciousCount}
              </span>
            </div>
            <div className="status-item">
              <span className="status-label">Last Updated</span>
              <span className="status-value">
                {lastUpdated
                  ? lastUpdated.toLocaleTimeString("en-IN", {
                      hour12: false,
                    })
                  : "—"}
              </span>
            </div>
          </div>

          {/* ALERTS WIDGET */}
          <div className="widget-wrapper" style={{ marginTop: "1.5rem" }}>
            <h3 className="widget-title">Alerts</h3>
            {alerts.length === 0 ? (
              <div className="empty-logs-message">No alerts detected</div>
            ) : (
              <ul className="alerts-list">
                {alerts.map((a, idx) => (
                  <li key={idx} className="alert-item">
                    {a.type === "SuspiciousDomain" ? (
                      <>
                        <span className="alert-icon">🚨</span>
                        <div className="alert-body">
                          <div className="alert-title">
                            Suspicious domain: <b>{a.domain}</b>
                          </div>
                          <div className="alert-meta">
                            Src: <b>{a.src_ip}</b>
                            {a.flags && a.flags.length > 0 && (
                              <>
                                {" "}
                                • Flags: {a.flags.join(", ")}
                              </>
                            )}{" "}
                            • {a.timestamp}
                          </div>
                        </div>
                      </>
                    ) : (
                      <>
                        <span className="alert-icon">⚠</span>
                        <div className="alert-body">
                          <div className="alert-title">
                            High frequency from <b>{a.src_ip}</b>
                          </div>
                          <div className="alert-meta">
                            {a.count} req/min • {a.timestamp}
                          </div>
                        </div>
                      </>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* CLOCK WIDGET */}
          <div className="clock-widget">
            <div className="clock-time">
              <span>{timeString[0]}</span>
              <span className="clock-colon">:</span>
              <span>{timeString[1]}</span>
              <span className="clock-colon">:</span>
              <span>{timeString[2]}</span>
            </div>
            <div className="clock-date">{dateString}</div>
          </div>
        </aside>

        {/* MAIN COLUMN */}
        <main className="main-column">
          {/* KPI CARDS */}
          <section className="kpi-grid widget-wrapper">
            <div className="kpi-card">
              <div className="kpi-label">Total Queries (current view)</div>
              <div className="kpi-value">{logs.length}</div>
              <div className="kpi-subtext">
                Latest 500 logs from live + API
              </div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">Unique Domains</div>
              <div className="kpi-value">{uniqueDomains}</div>
              <div className="kpi-subtext">
                Distinct FQDNs observed in logs
              </div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">Unique Source IPs</div>
              <div className="kpi-value">{uniqueIPs}</div>
              <div className="kpi-subtext">
                Client machines hitting DNS
              </div>
            </div>
            <div className="kpi-card">
              <div className="kpi-label">Suspicious Alerts</div>
              <div
                className="kpi-value"
                style={{ color: suspiciousCount ? "#ff4b4b" : "#00FF7F" }}
              >
                {suspiciousCount}
              </div>
              <div className="kpi-subtext">
                Based on suspicious-domain rules
              </div>
            </div>
          </section>

          {/* CHARTS ROW */}
          <section className="charts-grid">
            {/* Top Domains */}
            <div className="widget-wrapper">
              <h3 className="widget-title">Top Queried Domains</h3>
              <div style={{ width: "100%", height: 260 }}>
                <ResponsiveContainer>
                  <BarChart data={stats.topDomains}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="domain" hide />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="count" fill="#00eaff" />

                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Top IPs */}
            <div className="widget-wrapper">
              <h3 className="widget-title">Most Active Source IPs</h3>
              <div style={{ width: "100%", height: 260 }}>
                <ResponsiveContainer>
                  <PieChart>
                    <Pie
                      data={stats.topIPs}
                      dataKey="count"
                      nameKey="ip"
                      label
                    />
                    {stats.topIPs?.map((entry, index) => (
                      <Cell
                      key={`cell-${index}`}
                      fill={index % 2 === 0 ? "#00ff7f" : "#ff4d4d"} // green & red
                      />
                      ))}

                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          </section>

          {/* Line Chart */}
          <section className="widget-wrapper" style={{ marginTop: "1.5rem" }}>
            <h3 className="widget-title">Queries per Minute (Last 60 Minutes)</h3>
            <div style={{ width: "100%", height: 260 }}>
              <ResponsiveContainer>
                <LineChart data={stats.perMinute}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="minute" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="count" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </section>

          {/* LOG TABLE */}
          <section
            className="widget-wrapper"
            style={{ marginTop: "1.5rem", padding: "1.25rem" }}
          >
            <h3 className="widget-title">Live DNS Log Stream</h3>
            {logs.length === 0 ? (
              <div className="empty-logs-message">No DNS logs yet…</div>
            ) : (
              <div style={{ maxHeight: 320, overflowY: "auto" }}>
                <table className="dns-table">
                  <thead>
                    <tr>
                      <th>Domain</th>
                      <th>Source IP</th>
                      <th>Destination / Server</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map((r, i) => (
                      <tr key={i} className="log-row">
                        <td>{r.domain}</td>
                        <td>{r.src_ip}</td>
                        <td>{r.dst_ip || "-"}</td>
                        <td>{r.timestamp}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </main>
      </div>
    </div>
  );
}