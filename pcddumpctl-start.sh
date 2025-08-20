#!/bin/bash

set -e

# Detect the user's shell and set config file accordingly
if [ -n "$ZSH_VERSION" ] || [ "$(basename "$SHELL")" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
    SHELL_TYPE="zsh"
elif [ -n "$BASH_VERSION" ] || [ "$(basename "$SHELL")" = "bash" ]; then
    SHELL_RC="$HOME/.bashrc"
    SHELL_TYPE="bash"
else
    SHELL_RC="$HOME/.profile"
    SHELL_TYPE="profile"
fi

# Clone repo if not present
if [ ! -d "pcddumpctl" ]; then
    git clone https://github.com/vishnu-prasadtv/pcddumpctl.git
fi
cd pcddumpctl

# Create virtual environment if not present
if [ ! -d "pf9env" ]; then
    python3 -m venv pf9env
fi

# Activate the virtual environment
source pf9env/bin/activate

# Install required modules
pip install --upgrade pip
pip install -r requirements.txt

# Make the script executable
chmod +x pcddumpctl.py

# Copy binary to /usr/local/bin
sudo cp pcddumpctl.py /usr/local/bin/pcddumpctl

echo 'Now you are ready to use "pcddumpctl" or "pc" commands!'

# Add alias if not already present
if ! grep -q "alias pc=pcddumpctl" "$SHELL_RC"; then
    echo "alias pc=pcddumpctl" >> "$SHELL_RC"
    echo "Alias 'pc' added to $SHELL_RC"
else
    echo "Alias 'pc' already set in $SHELL_RC"
fi

# Source the rc file automatically
echo "Sourcing $SHELL_RC to activate the alias..."
source "$SHELL_RC"

echo "You can now use the 'pc' command, e.g.:"
echo "  pc get nodes"
