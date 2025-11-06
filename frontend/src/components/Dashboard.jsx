import React, { useEffect, useState } from "react";
import QueryTable from "./QueryTable";
import StatsCard from "./StatsCard";

const Dashboard = () => {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const res = await fetch("http://127.0.0.1:5000/api/logs");
        const data = await res.json();
        setLogs(data);
      } catch (error) {
        console.error("Error fetching logs:", error);
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 5000); // auto-refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard">
      <div className="stats">
        <StatsCard title="Total Queries" value={logs.length} />
      </div>
      <QueryTable logs={logs} />
    </div>
  );
};

export default Dashboard;
