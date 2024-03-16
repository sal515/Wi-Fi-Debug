# ################################################################################
# Constants
# ################################################################################

# ERROR CODES
ERROR_CODE_SUCCESS=0
ERROR_CODE_FAILURE=1
ERROR_CODE_NO_DEVICE=2
ERROR_CODE_NOT_FOUND=127

# Log levels
LOG_LEVEL_ERROR=0
LOG_LEVEL_INFO=1
LOG_LEVEL_DEBUG=2

# Set the current log level
CURRENT_LOG_LEVEL=$LOG_LEVEL_DEBUG

PRESERVE_GREP_COLOR="--color=always"

# ################################################################################
# Logging functions
# ################################################################################

info() {
    if [ $CURRENT_LOG_LEVEL -ge $LOG_LEVEL_INFO ]; then
        local MESSAGE=$1
        local TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
        echo "${TIMESTAMP} INFO ${MESSAGE}"
    fi
}

debug() {
    if [ $CURRENT_LOG_LEVEL -ge $LOG_LEVEL_DEBUG ]; then
        local MESSAGE=$1
        local TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
        echo "${TIMESTAMP} DEBUG ${MESSAGE}"
    fi
}

error() {
    if [ $CURRENT_LOG_LEVEL -ge $LOG_LEVEL_ERROR ]; then
        local MESSAGE=$1
        local TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
        echo "${TIMESTAMP} ERROR ${MESSAGE}" >&2
    fi
}

# ################################################################################
# Function Definitions
# ################################################################################

create_symbolic_link() {
    if [ ! -L /usr/local/bin/wifidbg ]; then
        sudo ln -s $(realpath $0) /usr/local/bin/wifidbg
        return $? # return the exit status of the last command
    fi
    return 0
}

enable_ssh_service() {
    sudo systemctl enable ssh
    sudo systemctl status ssh
}

find_network() {
    local interface=$1
    local ssid_name_pattern=$2

    if [ -z "$ssid_name_pattern" ]; then
        error "Error: SSID name pattern is required."
        exit $ERROR_CODE_FAILURE
    fi

    switch_wlan_interface_mode $interface managed

    debug "Scanning for SSID $ssid_name_pattern on interface $interface..."

    local scan_output=$(sudo iw "$interface" scan)
    # debug "scan_output: $scan_output"

    local bss_blocks=$(echo "$scan_output" |
        awk -v RS='\nBSS' -v IGNORECASE=1 -v pattern='ssid.{1,3}'"$ssid_name_pattern" '$0 ~ pattern')
    debug "bss_blocks: $bss_blocks"

    if [ -z "$bss_blocks" ]; then
        error "Error: SSID $ssid_name_pattern not found."
        exit $ERROR_CODE_FAILURE
    fi

    SSID_NAME=$(echo "$bss_blocks" |
        awk -F: 'BEGIN{IGNORECASE=1} /ssid/{print $2}' | tr -d ' ')
    debug "SSID_NAME: $SSID_NAME"

    SSID_CHANNEL=$(echo "$bss_blocks" |
        awk 'BEGIN{IGNORECASE=1} /DS Parameter set: channel/{print $5}' | tr -d ' ')
    debug "SSID_CHANNEL: $SSID_CHANNEL"

    switch_wlan_interface_mode $interface monitor
}

find_wlan_interface_in_monitor_mode() {
    # Get all wireless interfaces
    local interfaces=$(iwconfig 2>/dev/null | grep 'wlan' | awk '{print $1}')

    if [ -z "$interfaces" ]; then
        return $ERROR_CODE_NO_DEVICE
    else
        debug "Found the following wlan interfaces:"
        for interface in $interfaces; do
            debug $interface
            # Check if the interface is in monitor mode
            if iwconfig $interface | grep -iEq "Mode.*Monitor"; then
                debug "$interface is in monitor mode."
                MONITOR_MODE_INTERFACE=$interface
                return
            fi
        done
        return $ERROR_CODE_NOT_FOUND
    fi
}

interface_info() {
    INTERFACE=$1
    if [ -z "$INTERFACE" ]; then
        error "Error: Interface not found."
        exit 1
    fi

    info "Running interface info commands for $INTERFACE..."

    info "iwconfig $INTERFACE"
    iwconfig $INTERFACE | nl

    info "ip -s link show $INTERFACE"
    ip -s link show $INTERFACE | nl

    info "iw $INTERFACE info"
    iw $INTERFACE info | nl

    info "ethtool -i $INTERFACE"
    ethtool -i $INTERFACE | nl

    info "lshw -C network"
    sudo lshw -C network | nl

    # TODO FIXME Remove
    # info "iwlist $INTERFACE scan"
    # iwlist $INTERFACE scan | nl

    info "iw $INTERFACE scan"
    sudo iw dev $INTERFACE set type managed
    sudo iw $INTERFACE scan | nl
    sudo iw dev $INTERFACE set type monitor

}

start_mitmproxy() {
    local username=$1
    shift
    local ssl_key_log_file=$1
    shift
    local mitmproxy_ssl_insecure_option=$1
    shift
    local mitmproxy_as_root="" # todo fixme better structure to use sudo
    sudo -u ${username} setsid qterminal -e "bash -c '$mitmproxy_as_root SSLKEYLOGFILE=$ssl_key_log_file mitmproxy $mitmproxy_ssl_insecure_option; exec bash'" &
}

start_ssh_service() {
    sudo systemctl start ssh
    sudo systemctl status ssh
}

start_wireshark() {
    info "Starting wireshark and setting the tls.keylog_file..."
    if [ -n "$1" ]; then
        SSLKEYLOGFILE=$1
    fi
    info "SSL Key log file path set to $SSLKEYLOGFILE"
    nohup wireshark -o tls.keylog_file:$SSLKEYLOGFILE &>/dev/null &
}

switch_wlan_interface_mode() {
    INTERFACE=$1
    MODE=$2
    sudo ip link set $INTERFACE down
    sudo iw dev $INTERFACE set type $MODE
    sudo ip link set $INTERFACE up
}
