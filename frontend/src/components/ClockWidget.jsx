import React, { useState, useEffect } from 'react';

// A helper function to add a leading zero (e.g., 9 -> 09)
function formatTime(val) {
  return val.toString().padStart(2, '0');
}

function ClockWidget() {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    // Update the time every second
    const interval = setInterval(() => {
      setTime(new Date());
    }, 1000);

    // Clean up the interval when the component unmounts
    return () => clearInterval(interval);
  }, []);

  const hours = formatTime(time.getHours());
  const minutes = formatTime(time.getMinutes());
  const seconds = formatTime(time.getSeconds());
  const date = time.toLocaleDateString(undefined, {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  return (
    <div className="widget-wrapper clock-widget">
      <div className="clock-time">
        {hours}
        <span className="clock-colon">:</span>
        {minutes}
        <span className="clock-colon">:</span>
        {seconds}
      </div>
      <div className="clock-date">{date}</div>
    </div>
  );
}

export default ClockWidget;