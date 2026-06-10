#!/bin/bash
# Nexus Honeypot — Auto Setup Script

echo "🚀 Setting up Nexus Honeypot..."

# 1. Kill port 5000 if busy
sudo fuser -k 5000/tcp 2>/dev/null
echo "✅ Port 5000 cleared"

# 2. Create templates folder
mkdir -p templates
echo "✅ Templates folder ready"

# 3. Create .env if not exists
if [ ! -f .env ]; then
    cat > .env << 'EOF'
SECRET_KEY=Nexus@HoneypotSecretKey2025
ADMIN_USER=admin
ADMIN_PASS=Nexus@Admin2025
EOF
    echo "✅ .env file created"
else
    echo "✅ .env already exists"
fi

# 4. Create venv if not exists
if [ ! -d venv ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# 5. Activate and install packages
source venv/bin/activate
pip install flask flask-socketio flask-limiter requests python-dotenv -q
echo "✅ Packages installed"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Setup complete! Running app..."
echo "🌐 Open: http://localhost:5000"
echo "🔐 Admin: http://localhost:5000/admin"
echo "   User: admin | Pass: Nexus@Admin2025"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

python3 app.py