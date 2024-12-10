#!/bin/bash
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
clear
echo -e "${GREEN}"
echo "▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄"
echo "█                                          █"
echo "█   ███████ ██ ██      ███████ ███    ██  █"
echo "█   ██      ██ ██      ██      ████   ██  █"
echo "█   ███████ ██ ██      █████   ██ ██  ██  █"
echo "█        ██ ██ ██      ██      ██  ██ ██  █"
echo "█   ███████ ██ ███████ ███████ ██   ████  █"
echo "█                                          █"
echo "█   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀   █"
echo "█            SILENT GUARDIAN              █"
echo "█                 PushRSP      █"
echo "█   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   █"
echo "█                                          █"
echo "▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀"
echo -e "${NC}"
sleep 2

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        printf "\b\b\b\b\b\b"
        sleep $delay
    done
    printf "    \b\b\b\b"
}

execute_step() {
    local message=$1
    local command=$2
    
    echo -e "${BLUE}[*] ${message}...${NC}"
    eval $command &>/dev/null &
    spinner $!
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✔] ${message} - Completed${NC}"
    else
        echo -e "${RED}[✘] ${message} - Failed${NC}"
        exit 1
    fi
}

echo -e "\n${YELLOW}=== Silent Guardian Setup ===${NC}\n"
echo -e "${BLUE}[*] Checking Python installation...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[✘] Python 3 is not installed. Please install Python 3 first.${NC}"
    exit 1
else
    echo -e "${GREEN}[✔] Python 3 is installed${NC}"
fi

# Mode selection prompt
echo -e "\n${YELLOW}Select Mode:${NC}"
echo -e "${BLUE}1. CLI${NC}"
echo -e "${BLUE}2. Cracker${NC}"
read -p "Enter your choice (1/2): " mode_choice

echo -e "\n${YELLOW}=== System Configuration ===${NC}"
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo -e "${BLUE}[*] Detected OS: macOS${NC}"
    if ! python3 -c "import tkinter" &> /dev/null; then
        execute_step "Installing tkinter for macOS" "brew install python-tk"
    else
        echo -e "${GREEN}[✔] tkinter is already installed${NC}"
    fi
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "${BLUE}[*] Detected OS: Linux${NC}"
    if ! python3 -c "import tkinter" &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            echo -e "${BLUE}[*] Detected package manager: apt${NC}"
            execute_step "Updating package list" "sudo apt-get update"
            execute_step "Installing tkinter" "sudo apt-get install -y python3-tk"
        elif command -v dnf &> /dev/null; then
            echo -e "${BLUE}[*] Detected package manager: dnf${NC}"
            execute_step "Installing tkinter" "sudo dnf install -y python3-tkinter"
        elif command -v pacman &> /dev/null; then
            echo -e "${BLUE}[*] Detected package manager: pacman${NC}"
            execute_step "Installing tkinter" "sudo pacman -S tk --noconfirm"
        fi
    else
        echo -e "${GREEN}[✔] tkinter is already installed${NC}"
    fi
fi

echo -e "\n${YELLOW}=== Installing Python Packages ===${NC}"
execute_step "Installing required Python packages" "python3 -m pip install -q pyserial requests pyfiglet"

# Validate and launch corresponding script
case $mode_choice in
    1|cli|CLI)
        if [ ! -f "cli.py" ]; then
            echo -e "${RED}[✘] Error: cli.py not found in the current directory${NC}"
            exit 1
        fi
        echo -e "${GREEN}[*] Launching CLI mode...${NC}"
        python3 cli.py
        ;;
    2|cracker|CRACKER)
        if [ ! -f "cracker.py" ]; then
            echo -e "${RED}[✘] Error: cracker.py not found in the current directory${NC}"
            exit 1
        fi
        echo -e "${GREEN}[*] Launching Cracker mode...${NC}"
        python3 cracker.py
        ;;
    *)
        echo -e "${RED}[✘] Invalid choice. Please select 1 for CLI or 2 for Cracker.${NC}"
        exit 1
        ;;
esac
