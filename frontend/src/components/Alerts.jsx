export default function Alerts({ alerts }) {
  return (
    <div>
      {alerts.length === 0 && <p>No suspicious domains detected.</p>}

      {alerts.map((a, index) => (
        <div
          key={index}
          style={{
            background: "#330000",
            padding: "10px",
            marginBottom: "10px",
            border: "1px solid red",
          }}
        >
          <strong>Domain:</strong> {a.domain} <br />
          <strong>Source IP:</strong> {a.src_ip} <br />
          <strong>Flags:</strong> {a.flags.join(", ")} <br />
          <strong>Confidence:</strong> {a.confidence} <br />
          <strong>Timestamp:</strong> {a.timestamp}
        </div>
      ))}
    </div>
  );
}
