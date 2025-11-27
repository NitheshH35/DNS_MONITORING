import { BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, LineChart, Line, Legend, CartesianGrid } from "recharts";

export default function StatsCharts({ stats }) {
  return (
    <div>
      <h3>Top Domains</h3>
      <BarChart width={500} height={250} data={stats.topDomains}>
        <XAxis dataKey="domain" />
        <YAxis />
        <Tooltip />
        <Bar dataKey="count" />
      </BarChart>

      <h3>Top Source IPs</h3>
      <PieChart width={350} height={300}>
        <Pie data={stats.topIPs} dataKey="count" nameKey="ip" cx="50%" cy="50%" outerRadius={100} />
        <Tooltip />
      </PieChart>

      <h3>Queries per Minute</h3>
      <LineChart width={600} height={250} data={stats.perMinute}>
        <XAxis dataKey="minute" />
        <YAxis />
        <CartesianGrid stroke="#333" />
        <Tooltip />
        <Legend />
        <Line dataKey="count" />
      </LineChart>
    </div>
  );
}
