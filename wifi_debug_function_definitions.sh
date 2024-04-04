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

# Define color variables
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
MAGENTA='\e[35m'
CYAN='\e[36m'
WHITE='\e[37m'
RESET='\e[0m'

info() {
    if [ $CURRENT_LOG_LEVEL -ge $LOG_LEVEL_INFO ]; then
        local message=$1
        local color=$2
        local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
        echo -e "${timestamp} INFO ${color}${message}\e[0m"
    fi
}

debug() {
    if [ $CURRENT_LOG_LEVEL -ge $LOG_LEVEL_DEBUG ]; then
        local message=$1
        local color=$2
        local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
        echo -e "${timestamp} DEBUG ${color}${message}\e[0m"
    fi
}

error() {
    if [ $CURRENT_LOG_LEVEL -ge $LOG_LEVEL_ERROR ]; then
        local message=$1
        local color=$2
        local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
        echo -e "${timestamp} ERROR ${color}${message}\e[0m" >&2
    fi
}

# ################################################################################
# Internal functions
# ################################################################################

configure_wlan_interface() {
    local interface=${1:-"wlan0"}
    local mode=${2:-"monitor"}
    local channel=${3:--1}

    local iw_dev_interface_info_output=$(iw dev $interface info)
    local current_mode=$(echo "$iw_dev_interface_info_output" | grep -i "type" | awk '{print $2}')
    local current_channel=$(echo "$iw_dev_interface_info_output" | grep -i "channel" | awk '{print $2}')

    info "Current Config of interface $interface - Mode: $current_mode Channel: $current_channel"

    local update_mode=false
    local update_channel=false

    [ "$mode" != "$current_mode" ] && update_mode=true
    [ "$channel" -ge 0 ] && [ "$channel" != "$current_channel" ] && update_channel=true

    if [[ "$update_mode" = true || "$update_channel" = true ]]; then
        debug "Setting interface $interface down..."
        sudo ip link set $interface down
    fi

    [ "$update_mode" = true ] && debug "Setting interface $interface mode to $mode..." &&
        sudo iw dev $interface set type $mode

    [ "$update_channel" = true ] && debug "Setting interface $interface channel to $channel..." &&
        sudo iw dev $interface set channel $channel

    if [[ "$update_mode" = true || "$update_channel" = true ]]; then
        debug "Setting interface $interface up..."
        sudo ip link set $interface up
    fi

    # [ $channel -ge 0 ] && sudo iw dev $interface set channel $channel || :
    # # sudo iw dev $interface set type $mode
    # sudo ip link set $interface up
    # # sleep 2
    # # sudo systemctl restart NetworkManager
}

# ################################################################################
# Function Definitions
# ################################################################################

backup_wireshark_config() {
    local user_home="$1"
    local profile_name="$2"
    local backup_path_dir="$3"

    local wireshark_config_dir="$user_home/.config/wireshark"
    local wireshark_profiles_dir="$wireshark_config_dir/profiles"
    local wireshark_profile_dfilters_path="$wireshark_profiles_dir/$profile_name/dfilters"
    local wireshark_profile_preferences_path="$wireshark_profiles_dir/$profile_name/preferences"

    [ ! -f $wireshark_profile_dfilters_path ] &&
        error "Error: File not found: $wireshark_profile_dfilters_path" &&
        exit 1
    [ ! -f $wireshark_profile_preferences_path ] &&
        error "Error: File not found: $wireshark_profile_preferences_path" &&
        exit 1

    # NOTE: Example - To copy to the git repo directory
    # NOTE: If the git directory is mounted on VM and the script is on the VM,
    # fatal: detected dubious ownership in repository at '/home/kali/wifi_debug'
    # To add an exception for this directory, call:
    # git config --global --add safe.directory /home/kali/wifi_debug
    # ==============================================================
    # cd ${SCRIPT_DIR}"/"
    # git_root_dir=$(git rev-parse --show-toplevel 2>/dev/null)
    # if [ -z "$git_root_dir" ]; then
    #   echo "Error: This script must be run in a Git repository"
    #   exit 1
    # fi
    # wireshark_config_backup_dir="$git_root_dir/wireshark_config/$profile_name"

    local wireshark_config_backup_dir="$backup_path_dir/$profile_name"
    [ ! -d "$wireshark_config_backup_dir" ] && mkdir -p "$wireshark_config_backup_dir"
    cp $wireshark_profile_dfilters_path "$wireshark_config_backup_dir/dfilters"
    cp $wireshark_profile_preferences_path "$wireshark_config_backup_dir/preferences"
}

create_symbolic_link() {
    debug "Creating symbolic link [wifidbg] for this script..."
    if [ ! -L /usr/local/bin/wifidbg ]; then
        sudo chmod +x $(realpath $0)
        sudo ln -s $(realpath $0) /usr/local/bin/wifidbg
        return $? # return the exit status of the last command
    fi
    return 0
}

enable_ssh_service() {
    sudo systemctl enable ssh
    sudo systemctl status ssh
}

find_ssid_channel_using_airodump_ng() {
    local interface=$1
    shift
    local script_dir=$1
    shift
    local output_dir="$script_dir/airodump_log"
    local log_format="kismet"
    [ -d "$output_dir" ] && rm -rf $output_dir
    mkdir -p $output_dir

    sudo airodump-ng --output-format $log_format -w "$output_dir/airodumplog" $interface
    SSID=$(grep -iE "tp.*link" "$output_dir/airodumplog-01.kismet.csv" | awk -F ';' '{print $3}')
    CHANNEL=$(grep -iE "tp.*link" "$output_dir/airodumplog-01.kismet.csv" | awk -F ';' '{print $6}')
}

find_ssid_channel() {
    local interface=$1
    local ssid_name_pattern=$2

    if [ -z "$ssid_name_pattern" ]; then
        error "Error: SSID name pattern is required."
        exit $ERROR_CODE_FAILURE
    fi

    configure_wlan_interface $interface managed

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

wlan_iw_info() {
    local interface=$1
    shift
    info "iw $interface info"
    iw $interface info | nl
}

wlan_all_info() {
    local interface=$1
    shift
    if [ -z "$interface" ]; then
        error "Error: Interface not found."
        exit 1
    fi
    info "Running interface info commands for $interface..."

    read -p "Do you want to clear the terminal? (y/n) " -n 1 -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        clear
    fi

    info "iwconfig $interface"
    iwconfig $interface | nl

    info "ip -s link show $interface"
    ip -s link show $interface | nl

    wlan_iw_info $interface

    info "ethtool -i $interface"
    ethtool -i $interface | nl

    info "lshw -C network"
    sudo lshw -C network | nl

    # sleep 3
    # read -p "Do you want to perform a network scan? (y/n) " -n 1 -r
    # if [[ $REPLY =~ ^[Yy]$ ]]; then
    #     info "iw $interface scan"
    #     configure_wlan_interface $interface managed
    #     sudo iw $interface scan | nl
    #     configure_wlan_interface $interface monitor
    # fi
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
    local ssl_key_log_file=$1
    nohup wireshark -o tls.keylog_file:$ssl_key_log_file &>/dev/null &
}

setup_interface_in_monitor_mode() {
    local interface=$1
    shift
    local channel=$1
    shift
    configure_wlan_interface $interface "monitor" $channel
    # sudo systemctl restart NetworkManager
    wlan_iw_info $interface
}

setup_ssh_pub_key_usage_and_append_pub_ssh_key() {
    ssh_authorized_keys_filepath=$1
    sshd_config_filepath=$2
    ssh_public_key=$3

    if [ ! -f "$ssh_authorized_keys_filepath" ]; then
        touch $ssh_authorized_keys_filepath || {
            error "Failed to create SSH authorized keys file"
            exit 1
        }
    fi

    if grep -q "^#PubkeyAuthentication" "$sshd_config_filepath"; then
        debug "PubkeyAuthentication is commented out" && { grep "^#PubkeyAuthentication" "$sshd_config_filepath"; }
        info "PubkeyAuthentication is uncommented" && sudo sed -i 's/^#PubkeyAuthentication/PubkeyAuthentication/' "$sshd_config_filepath"
    fi

    if grep -q "^PubkeyAuthentication no" "$sshd_config_filepath"; then
        debug "PubkeyAuthentication is set to no" && { grep "^PubkeyAuthentication no" "$sshd_config_filepath"; }
        info "PubkeyAuthentication is set to yes" && sudo sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' "$sshd_config_filepath"
    fi

    if grep -q "^#AuthorizedKeysFile" "$sshd_config_filepath"; then
        debug "AuthorizedKeysFile is commented out" && { grep "^#PubkeyAuthentication" "$sshd_config_filepath"; }
        info "AuthorizedKeysFile is uncommented" && sudo sed -i 's/^#AuthorizedKeysFile/AuthorizedKeysFile/' "$sshd_config_filepath"
    fi

    if grep -Fq "$ssh_public_key" "$ssh_authorized_keys_filepath"; then
        echo "The SSH public key already exists in the authorized_keys file"
    else
        echo "The SSH public key does not exist in the authorized_keys file"
        echo "$ssh_public_key" >>$ssh_authorized_keys_filepath

    fi
    sudo systemctl restart ssh

    #debug
    authorized_key_file_content=$(cat $ssh_authorized_keys_filepath)
    debug "$authorized_key_file_content"
}
