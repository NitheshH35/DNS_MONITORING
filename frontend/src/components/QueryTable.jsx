import React from "react";

const QueryTable = ({ logs }) => (
  <table>
    <thead>
      <tr>
        <th>Domain</th>
        <th>Source IP</th>
        <th>Timestamp</th>
      </tr>
    </thead>
    <tbody>
      {logs.map((log, index) => (
        <tr key={index}>
          <td>{log.domain}</td>
          <td>{log.src_ip}</td>
          <td>{log.timestamp}</td>
        </tr>
      ))}
    </tbody>
  </table>
);

export default QueryTable;
