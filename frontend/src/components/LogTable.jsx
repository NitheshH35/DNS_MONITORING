export default function LogTable({ logs }) {
  return (
    <table border="1" style={{ width: "100%", background: "#222", color: "white" }}>
      <thead>
        <tr>
          <th>Domain</th>
          <th>Source IP</th>
          <th>Destination IP</th>
          <th>Timestamp</th>
        </tr>
      </thead>

      <tbody>
        {logs.map((log, i) => (
          <tr key={i}>
            <td>{log.domain}</td>
            <td>{log.src_ip}</td>
            <td>{log.dst_ip || "N/A"}</td>
            <td>{log.timestamp}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
