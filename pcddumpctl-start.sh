#!/bin/bash

# Clone repo
git clone https://github.com/vishnu-prasadtv/pcddumpctl.git
cd pcddumpctl

# Create virtual environment
python3 -m venv pf9env

# Activate the virtual environment
source pf9env/bin/activate

# Install module required:
pip install --upgrade pip
echo "pyyaml>=5.3.1
tabulate>=0.8.9"
pip install -r requirements.txt

# Execute permission 
chmod +x pcddumpctl.py

# Adding Binary
sudo cp pcddumpctl.py /usr/local/bin/pcddumpctl

echo 'Now you are ready to use "pcddumpctl" or "pc" commands!'

# Alias
alias pc=pcddumpctl
echo "alias pc=pcddumpctl" >> ~/.bash_profile
echo "alias pc=pcddumpctl" >> ~/.bashrc
source ~/.bash_profile
source ~/.bashrc
# Edit /etc/bashrc or /etc/profile.d/custom_aliases.sh
sudo sh -c 'echo "alias pc=pcddumpctl" >> /etc/bashrc'
sudo sh -c 'echo "alias pc=pcddumpctl" > /etc/profile.d/custom_aliases.sh'
