#!/bin/bash

# MISP MCP Server Runner Script
# This script sets up the environment and runs the MISP MCP server

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for Python
check_python() {
    if ! command_exists python3; then
        print_error "Python 3 is not installed or not in PATH"
        exit 1
    fi
    
    local python_version
    python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
    print_info "Found Python $python_version"
}

# Check for UV package manager
check_uv() {
    if ! command_exists uv; then
        print_warning "UV package manager not found. Installing UV..."
        if command_exists curl; then
            curl -LsSf https://astral.sh/uv/install.sh | sh
            # Source the shell profile to get uv in PATH
            export PATH="$HOME/.cargo/bin:$PATH"
        else
            print_error "UV package manager not found and curl is not available to install it"
            print_info "Please install UV manually: https://docs.astral.sh/uv/getting-started/installation/"
            exit 1
        fi
    fi
    
    print_success "UV package manager found"
}

# Check for environment file
check_environment() {
    if [[ ! -f ".env" ]]; then
        print_warning "No .env file found"
        
        # Check if .env.example exists
        if [[ -f ".env.example" ]]; then
            print_info "Found .env.example. You may want to copy it to .env and configure it:"
            print_info "cp .env.example .env"
        else
            print_info "Please create a .env file with the following variables:"
            print_info "MISP_URL=https://your-misp-instance.com"
            print_info "MISP_API_KEY=your_api_key_here"
            print_info "MISP_VERIFY_SSL=true"
            print_info "MCP_SERVER_HOST=localhost"
            print_info "MCP_SERVER_PORT=8000"
        fi
        
        # Ask if user wants to continue anyway
        read -p "Continue without .env file? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Exiting. Please set up your environment first."
            exit 1
        fi
    else
        print_success "Found .env file"
    fi
}

# Install dependencies if needed
install_dependencies() {
    print_info "Checking and installing dependencies..."
    
    if [[ -f "uv.lock" ]]; then
        uv sync
        print_success "Dependencies synchronized"
    elif [[ -f "pyproject.toml" ]]; then
        uv install
        print_success "Dependencies installed"
    else
        print_error "No pyproject.toml or uv.lock found"
        exit 1
    fi
}

# Run the server
run_server() {
    print_info "Starting MISP MCP Server..."
    echo
    
    # Run using uv to ensure virtual environment is used
    # Use -m to run as module so relative imports work
    uv run python -m app.server
}

# Main execution
main() {
    print_info "MISP MCP Server Runner"
    print_info "======================"
    echo
    
    # Change to script directory
    cd "$(dirname "$0")"
    
    # Perform checks
    check_python
    check_uv
    check_environment
    install_dependencies
    
    echo
    print_info "All checks passed. Starting server..."
    echo
    
    # Run the server
    run_server
}

# Handle script interruption
trap 'print_info "Server stopped by user"; exit 0' INT

# Run main function
main "$@" 