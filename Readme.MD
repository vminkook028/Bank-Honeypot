# 🍯 Nexus Honeypot v2.0

A fake bank login page that captures attacker credentials and shows them on a live dashboard.

## Features
- Fake login page (honeypot)
- Real-time attack dashboard
- IP geolocation tracking
- CSV export of logs
- Rate limiting

## Setup

### 1. Clone the repo
```bash
git clone https://github.com/your-username/honeypot.git
cd honeypot
```

### 2. Create `.env` file
```bash
cp .env.example .env
nano .env   # Fill in your values
```

### 3. Create virtual environment & install packages
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Run
```bash
python3 app.py
```

### 5. Open in browser
| URL | Description |
|-----|-------------|
| `http://localhost:5000` | Honeypot fake login |
| `http://localhost:5000/admin` | Admin login |
| `http://localhost:5000/dashboard` | Live attack dashboard |

## ⚠️ Warning
This tool is for **educational and research purposes only**.  
Deploy only on systems you own or have permission to monitor.