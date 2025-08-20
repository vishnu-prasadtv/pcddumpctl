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
# Function to check if alias exists
check_and_set_alias() {
    # Check if alias is already defined
    if ! alias pc 2>/dev/null; then
        # Add alias to bash profile and bashrc
        echo "alias pc=pcddumpctl" >> ~/.bash_profile
        echo "alias pc=pcddumpctl" >> ~/.bashrc
        
        # Source the profile files to apply immediately
        source ~/.bash_profile
        source ~/.bashrc
        
        echo "Alias 'pc' has been created."
        return 0
    else
        echo "Alias 'pc' already exists."
        return 1
    fi
}

# Main script
if check_and_set_alias; then
    echo "Alias 'pc' is successfully exported. Start using Example: 'pc api-resources'""
else
    echo "Alias 'pc' already present. Start using Example: 'pc api-resources'"
fi
