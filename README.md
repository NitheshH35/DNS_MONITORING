# DNS Monitoring

A lightweight **DNS Monitoring System** that captures DNS queries from the local network, stores them in an SQLite database, and visualizes them on a **real-time dashboard** built with React + Recharts.
The backend uses **Flask + Socket.IO** and supports packet sniffing via **Scapy**.

This project is designed for learning, monitoring, and analysing DNS traffic with charts, live logs, domain categorization, and CSV export.

---

## 📁 Project Structure

```
DNS_MONITORING/
│
├── backend/
│   ├── app.py               # Main Flask backend API + Socket.IO server
│   ├── monitor.py           # DNS packet sniffing & ingestion
│   ├── db.sqlite3           # Auto-created SQLite DB
│   ├── requirements.txt     # Backend dependencies
│   └── ...
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx          # Dashboard UI
│   │   └── components/...   # Charts & UI components
│   ├── package.json
│   └── ...
│
└── README.md
```

---

# ✨ Features

* 📡 **DNS Packet Sniffing** (Scapy)
* 💾 **SQLite storage** for DNS logs
* 📊 **Live Dashboard**

  * Top domains
  * Query frequency
  * Line chart, bar chart, pie chart
  * Recent DNS logs table
* 🔄 **Real-time updates** using Socket.IO
* 🔍 **TLD extraction & WHOIS domain enrichment**
* 📤 **Export logs to CSV**
* 🌙 **Dark mode support (frontend-ready)**

---

# 🧰 Requirements

### Backend

* Python **3.9+**
* Scapy
* Flask
* Flask-SocketIO
* tldextract
* whois
* idna

(Installed automatically using `pip install -r requirements.txt`)

### Frontend

* Node.js **16+**
* React
* Recharts
* Socket.IO client

### System Requirements

* **Admin/root access** if packet sniffing is used

  * Windows → Run terminal as **Administrator**
  * Linux → Use `sudo`

---

# 🚀 How to Run the Project

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/NitheshH35/DNS_MONITORING.git
cd DNS_MONITORING
```

---

# 🖥️ Backend Setup (Flask API + Socket.IO)

### 1. Create a virtual environment

```bash
cd backend
python -m venv venv
```

#### Windows:

```bash
venv\Scripts\activate
```

#### Linux / Mac:

```bash
source venv/bin/activate
```

---

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 3. Run the backend server

```bash
python app.py
```

Backend will run at:

```
http://127.0.0.1:5000
```

---

# 🛰️ Packet Sniffing Setup

If you want live DNS capture:

### Linux:

```bash
sudo python monitor.py
```

### Windows:

* Install **Npcap**
* Run CMD/Powershell as **Administrator**

```bash
python monitor.py
```

The sniffed DNS data will automatically appear in your dashboard.

---

# 💻 Frontend Setup (React Dashboard)

Open a second terminal:

```bash
cd frontend
npm install
```

### Start the app

```bash
npm start
```

Frontend will run at:

```
http://localhost:3000
```

It will automatically connect to:

```
http://127.0.0.1:5000
```

---

# 📤 Export CSV

The dashboard has an **Export CSV** button that calls:

```
GET /export
```

The backend generates a CSV from SQLite and triggers download.

If you see date/time as ####### in Excel:

* Format the column → "Text" or "Short date"

---

# 🛠️ Common Issues & Fixes

### ❗ Export CSV not downloading / blank

* Ensure your backend route:

```python
@app.route('/export')
```

returns `send_file()` or `Response()` correctly.

* Disable dark mode CSS affecting button visibility.

### ❗ Monitor not capturing DNS

* Run as administrator / sudo.
* Ensure network interface is correct.
* Install Npcap (Windows).

### ❗ Socket.IO not updating UI

* Check CORS settings in `app.py`
* Verify frontend uses:
  `io("http://127.0.0.1:5000")`

---

# 📌 Future Improvements (Optional)

* Add authentication
* Add GeoIP lookup
* Add filtering/search in logs table
* Deploy using Docker
* Upload pcap for offline analysis

---


