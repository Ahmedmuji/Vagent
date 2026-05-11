#!/bin/bash
set -e

echo "==========================================="
echo "   Vagent Server Deployment Script"
echo "==========================================="

# 1. Update system and install Python 3 venv if needed
# sudo apt update && sudo apt install python3-venv python3-pip -y

# 2. Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# 3. Activate and install dependencies
echo "Installing dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 4. Check for .env
if [ ! -f ".env" ]; then
    echo ""
    echo "WARNING: .env file not found!"
    echo "Please create a .env file with the following variables:"
    echo "GEMINI_API_KEY=your_key_here"
    echo "FLASK_SECRET_KEY=your_secret_here"
    echo "SERVER_BASE_URL=http://your-server-ip:5000"
    echo ""
    exit 1
fi

# 5. Check for the 134MB PDF
PDF_PATH="data/Reference dataset/FortiOS-7.6.6-Administration_Guide.pdf"
if [ ! -f "$PDF_PATH" ]; then
    echo ""
    echo "WARNING: Admin Guide PDF missing!"
    echo "Please copy the 134MB FortiOS-7.6.6-Administration_Guide.pdf into:"
    echo "  $PDF_PATH"
    echo ""
    exit 1
fi

# 6. Start Gunicorn Server
echo "Starting Vagent Server on port 5000..."
echo "Press Ctrl+C to stop."
echo "For background execution, run: nohup gunicorn --bind 0.0.0.0:5000 --timeout 600 app:app > vagent.log 2>&1 &"

# Start in foreground for testing, with a massive timeout
gunicorn --bind 0.0.0.0:5000 --timeout 600 app:app
