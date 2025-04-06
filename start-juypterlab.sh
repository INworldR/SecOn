#!/bin/zsh
#
# start-jupyterlab.sh
# Starts JupyterLab in a screen session using conda environment with zsh shell
#

# Configuration
CONDA_ENV="secon"
APP_PATH="/Users/marc/Documents/INcode/SecON"
SCREEN_NAME="jupyterlab-secon"
PORT=8888

# Get current hostname and OS type
HOSTNAME=$(hostname -s)
OS_TYPE=$(uname)

# Function to get IP address based on OS
get_ip_address() {
    if [[ "$OS_TYPE" == "Darwin" ]]; then  # macOS
        # Use ipconfig to get IP on macOS
        ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "127.0.0.1"
    else  # Linux and others
        hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1"
    fi
}

# Process command line arguments
while getopts "p:" opt; do
    case $opt in
        p) PORT="$OPTARG" ;;
        *) echo "Usage: $0 [-p port]  # Default port is 8898" && exit 1 ;;
    esac
done

# Check dependencies
if ! command -v screen > /dev/null; then
    echo "Error: screen is not installed"
    exit 1
fi

if ! command -v conda > /dev/null; then
    echo "Error: conda is not installed"
    exit 1
fi

# Check if the screen session already exists
if screen -list | grep -q "$SCREEN_NAME"; then
    echo "Error: Screen session '$SCREEN_NAME' already exists"
    echo "To resume the session: screen -r $SCREEN_NAME"
    echo "To kill the session: screen -X -S $SCREEN_NAME quit"
    exit 1
fi

# Ensure we're in the correct directory
cd "$APP_PATH" || exit 1

# Set ip address based on hostname
if [[ "$HOSTNAME" == "dogo" ]]; then
    IP_ADDR="0.0.0.0"
    echo "Detected host 'dogo': JupyterLab will listen on all interfaces (0.0.0.0)"
else
    IP_ADDR="127.0.0.1"
    echo "JupyterLab will only listen on localhost (127.0.0.1)"
fi

# Create the screen session and run JupyterLab using zsh with profile loaded
screen -dmS "$SCREEN_NAME" zsh -c "source $HOME/.zprofile && conda activate $CONDA_ENV && jupyter lab --ip=$IP_ADDR --port=$PORT --no-browser; exec zsh"

# Check if screen session was created successfully
if screen -list | grep -q "$SCREEN_NAME"; then
    echo "Successfully started JupyterLab in conda environment $CONDA_ENV on port $PORT"
    echo "Screen session name: $SCREEN_NAME"
    echo "To attach to the session: screen -r $SCREEN_NAME"
    echo "To detach from session: Ctrl+A, D"
    echo "To kill the session: screen -X -S $SCREEN_NAME quit"
    
    if [[ "$HOSTNAME" == "dogo" ]]; then
        IP=$(get_ip_address)
        echo "JupyterLab is accessible at:"
        echo "  - http://localhost:$PORT (on the server)"
        echo "  - http://dogo:$PORT (from other machines on the network)"
        echo "  - http://$IP:$PORT (using IP address)"
    else
        echo "JupyterLab should be accessible at http://localhost:$PORT"
    fi
    
    echo "Using shell: zsh with sourced ~/.zprofile"
else
    echo "Error: Failed to create screen session"
    exit 1
fi
