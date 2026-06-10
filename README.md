# 🏦 Bank Honeypot

A cybersecurity tool that simulates a fake bank login page to capture and analyze attacker behavior in real-time.

## 🔍 Overview

Bank Honeypot is a Python-based honeypot system designed for educational and research purposes. It lures attackers with a realistic bank login interface while silently logging their credentials, IP addresses, and geolocation data.

## ✨ Features
- 🎣 Fake bank login page to trap attackers
- 📊 Real-time attack dashboard
- 🌍 IP geolocation tracking
- 🔐 Secure admin panel
- 📁 CSV export of attack logs
- ⚡ Live updates via WebSocket
- 🛡️ Rate limiting to prevent abuse

## 🛠️ Tech Stack
- Python 3
- Flask
- Flask-SocketIO
- Flask-Limiter
- HTML / CSS / JavaScript

## ⚙️ Setup & Installation

### 1. Clone the repository
git clone https://github.com/vminkook028/Bank-Honeypot.git
cd Bank-Honeypot

2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

### 3. Install dependencies
pip install -r requirements.txt

### 4. Configure environment
cp .env.example .env
nano .env

### 5. Run the application
python3 app.py

## 🌐 Access
| Page | URL |
| Honeypot Login | http://localhost:5000 |
| Admin Panel | http://localhost:5000/admin |
| Dashboard | http://localhost:5000/dashboard |

## ⚠️ Disclaimer
This tool is developed strictly for educational and cybersecurity research purposes. Only deploy on systems you own or have explicit permission to monitor. Unauthorized use is illegal.

## 👩‍💻 Author
Amisha Prajapati 
