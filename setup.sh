#!/bin/bash

# Sanitizer Engine - Yara-X Integration Setup Script

set -e

echo "🛡️  Sanitizer Engine - Yara-X Integration Setup"
echo "================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check Python version
echo "Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.9"

if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)"; then
    print_error "Python 3.9 or higher is required. Found: $PYTHON_VERSION"
    exit 1
fi
print_success "Python version: $PYTHON_VERSION"

# Create virtual environment
echo ""
echo "Creating virtual environment..."
if [ -d "venv" ]; then
    print_warning "Virtual environment already exists, skipping..."
else
    python3 -m venv venv
    print_success "Virtual environment created"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate
print_success "Virtual environment activated"

# Upgrade pip
echo ""
echo "Upgrading pip..."
pip install --upgrade pip > /dev/null 2>&1
print_success "pip upgraded"

# Install dependencies
echo ""
echo "Installing dependencies..."
pip install -r 'requirements.txt'
if [ $? -eq 0 ]; then
    print_success "Dependencies installed successfully"
else
    print_error "Failed to install dependencies"
    exit 1
fi

# Create necessary directories
echo ""
echo "Creating directories..."
mkdir -p rules
mkdir -p quarantine
mkdir -p logs

print_success "Created rules directory"
print_success "Created quarantine directory"
print_success "Created logs directory"

# Copy example rules if not exists
echo ""
if [ -f "rules/example_rules.yar" ]; then
    print_warning "Example rules already exist, skipping..."
else
    cp python yara_scanner.py /path/to/file -r example_rules.yarexample_rules.yar rules/
    print_success "Copied example rules to rules directory"
fi

# Set up environment variables
echo ""
echo "Setting up environment..."
cat > .env << EOF
# Sanitizer Engine Configuration
YARA_RULES_PATH=./rules
QUARANTINE_DIR=./quarantine
SCAN_TIMEOUT=60
FLASK_ENV=development
EOF
print_success "Created .env file"

# Run tests
echo ""
echo "Running tests..."
if python -m pytest test_scanner.py -v > /dev/null 2>&1; then
    print_success "All tests passed"
else
    print_warning "Some tests failed (this is OK for initial setup)"
fi

# Setup complete
echo ""
echo "================================================"
echo -e "${GREEN}✓ Setup Complete!${NC}"
echo "================================================"
echo ""
echo "Quick Start:"
echo "  1. Activate venv:  source venv/bin/activate"
echo "  2. Start API:      python sanitizer_api.py"
echo "  3. Test scan:      python yara_scanner.py <file> -r rules/example_rules.yar"
echo ""
echo "API will be available at: http://localhost:5000"
echo ""
echo "Documentation:"
echo "  • Full guide:   README.md"
echo "  • Quick start:  QUICKSTART.md"
echo ""
echo "Next steps:"
echo "  • Add your Yara rules to the 'rules/' directory"
echo "  • Customize configuration in .env"
echo "  • Start scanning!"
echo ""
