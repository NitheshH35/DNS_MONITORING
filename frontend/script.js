async function fetchDNSData() {
  const res = await fetch("/api/dns");
  const data = await res.json();
  return data;
}

async function renderDashboard() {
  const data = await fetchDNSData();

  // Chart: Top Queried Domains
  const domainCounts = {};
  data.forEach(d => {
    domainCounts[d.query_name] = (domainCounts[d.query_name] || 0) + 1;
  });

  const ctx = document.getElementById("dnsChart").getContext("2d");
  new Chart(ctx, {
    type: "bar",
    data: {
      labels: Object.keys(domainCounts),
      datasets: [{
        label: "Query Count",
        data: Object.values(domainCounts),
        borderWidth: 1
      }]
    }
  });

  // Table
  let tableHTML = "<table><tr><th>Timestamp</th><th>Query</th><th>Src IP</th><th>Dest IP</th><th>Status</th></tr>";
  data.forEach(row => {
    tableHTML += `<tr>
      <td>${row.timestamp}</td>
      <td>${row.query_name}</td>
      <td>${row.source_ip}</td>
      <td>${row.destination_ip}</td>
      <td>${row.status}</td>
    </tr>`;
  });
  tableHTML += "</table>";

  document.getElementById("logTable").innerHTML = tableHTML;
}

renderDashboard();
setInterval(renderDashboard, 5000);
