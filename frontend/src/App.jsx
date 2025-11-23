// frontend/src/App.jsx
import { useEffect, useMemo, useState } from "react";
import io from "socket.io-client";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, LineChart, Line, CartesianGrid, Legend,
} from "recharts";

const API = "http://127.0.0.1:5000";

export default function App() {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({ topDomains: [], topIPs: [], perMinute: [] });
  const [alerts, setAlerts] = useState([]);
  const [dark, setDark] = useState(false);

  // initial fetch + polling (backup if websocket disconnects)
  useEffect(() => {
    const fetchAll = async () => {
      const [l, s, a] = await Promise.all([
        fetch(`${API}/logs`).then(r => r.json()),
        fetch(`${API}/stats`).then(r => r.json()),
        fetch(`${API}/alerts`).then(r => r.json()),
      ]);
      setLogs(l);
      setStats(s);
      setAlerts(a.alerts || []);
    };
    fetchAll();
    const t = setInterval(fetchAll, 5000);
    return () => clearInterval(t);
  }, []);

  // WebSocket: push new logs live
  useEffect(() => {
    const socket = io(API, { transports: ["websocket"] });
    socket.on("connect", () => console.log("WS connected"));
    socket.on("new_log", (msg) => {
      setLogs(prev => [msg, ...prev].slice(0, 500));
    });
    socket.on("disconnect", () => console.log("WS disconnected"));
    return () => socket.close();
  }, []);

  const tableBg = dark ? "#0f172a" : "#fff";
  const text = dark ? "#e2e8f0" : "#000";
  const card = dark ? "#111827" : "#f8fafc";
  const border = dark ? "#374151" : "#e5e7eb";
  const page = dark ? "#0b1020" : "#f4f7fc";

  const exportCsv = () => {
    window.location.href = `${API}/export/csv`;
  };

  const suspiciousCount = useMemo(() => alerts.filter(a => a.type === "SuspiciousDomain").length, [alerts]);

  return (
    <div style={{ minHeight: "100vh", background: page, color: text, fontFamily: "Inter, Arial, sans-serif", padding: 16 }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <h1 style={{ margin: 0 }}>🌐 DNS Monitoring Dashboard</h1>
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={exportCsv} style={{ padding: "8px 12px", borderRadius: 8, border: `1px solid ${border}`, background: card, color: text }}>⬇ Export CSV</button>
          <button onClick={() => setDark(x => !x)} style={{ padding: "8px 12px", borderRadius: 8, border: `1px solid ${border}`, background: card, color: text }}>
            {dark ? "☀ Light" : "🌙 Dark"}
          </button>
        </div>
      </header>

      {/* KPI cards */}
      <section style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, marginBottom: 16 }}>
        <div style={{ background: card, border: `1px solid ${border}`, borderRadius: 12, padding: 16 }}>
          <div>Total Queries</div>
          <div style={{ fontSize: 28, fontWeight: 700 }}>{logs.length}</div>
        </div>
        <div style={{ background: card, border: `1px solid ${border}`, borderRadius: 12, padding: 16 }}>
          <div>Unique Domains</div>
          <div style={{ fontSize: 28, fontWeight: 700 }}>{new Set(logs.map(l => l.domain)).size}</div>
        </div>
        <div style={{ background: card, border: `1px solid ${border}`, borderRadius: 12, padding: 16 }}>
          <div>Unique IPs</div>
          <div style={{ fontSize: 28, fontWeight: 700 }}>{new Set(logs.map(l => l.src_ip)).size}</div>
        </div>
        <div style={{ background: card, border: `1px solid ${border}`, borderRadius: 12, padding: 16 }}>
          <div>Suspicious Alerts</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: suspiciousCount ? "#ef4444" : text }}>{suspiciousCount}</div>
        </div>
      </section>

      {/* Charts */}
      <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
        <div style={{ background: card, border: `1px solid ${border}`, borderRadius: 12, padding: 8, minHeight: 320 }}>
          <h3 style={{ margin: 8 }}>Top Domains</h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={stats.topDomains}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="domain" hide />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div style={{ background: card, border: `1px solid ${border}`, borderRadius: 12, padding: 8, minHeight: 320 }}>
          <h3 style={{ margin: 8 }}>Most Active IPs</h3>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie data={stats.topIPs} dataKey="count" nameKey="ip" label />
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section style={{ background: card, border: `1px solid ${border}`, borderRadius: 12, padding: 8, marginBottom: 16 }}>
        <h3 style={{ margin: 8 }}>Queries per Minute (Last 60m)</h3>
        <ResponsiveContainer width="100%" height={260}>
          <LineChart data={stats.perMinute}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="minute" />
            <YAxis />
            <Tooltip />
            <Legend />
            <Line type="monotone" dataKey="count" />
          </LineChart>
        </ResponsiveContainer>
      </section>

      {/* Alerts */}
      <section style={{ background: card, border: `1px solid ${border}`, borderRadius: 12, padding: 12, marginBottom: 16 }}>
        <h3 style={{ margin: 0, marginBottom: 8 }}>Alerts</h3>
        {alerts.length === 0 ? (
          <div>No alerts</div>
        ) : (
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {alerts.map((a, idx) => (
              <li key={idx} style={{ marginBottom: 6 }}>
                {a.type === "SuspiciousDomain" ? (
                  <span>🚨 <b>{a.domain}</b> from <b>{a.src_ip}</b> [{(a.flags||[]).join(', ')}] at {a.timestamp}</span>
                ) : (
                  <span>⚠ High frequency from <b>{a.src_ip}</b>: {a.count} req/min</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Table */}
      <section style={{ background: tableBg, border: `1px solid ${border}`, borderRadius: 12, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead style={{ background: dark ? "#111827" : "#e5e7eb" }}>
            <tr>
              <th style={{ textAlign: "left", padding: 10, borderBottom: `1px solid ${border}` }}>Domain</th>
              <th style={{ textAlign: "left", padding: 10, borderBottom: `1px solid ${border}` }}>Source IP</th>
              <th style={{ textAlign: "left", padding: 10, borderBottom: `1px solid ${border}` }}>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((r, i) => (
              <tr key={i} style={{ borderBottom: `1px solid ${border}` }}>
                <td style={{ padding: 10 }}>{r.domain}</td>
                <td style={{ padding: 10 }}>{r.src_ip}</td>
                <td style={{ padding: 10 }}>{r.timestamp}</td>
              </tr>
            ))}
            {logs.length === 0 && (
              <tr><td colSpan="3" style={{ padding: 12 }}>No DNS logs…</td></tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
