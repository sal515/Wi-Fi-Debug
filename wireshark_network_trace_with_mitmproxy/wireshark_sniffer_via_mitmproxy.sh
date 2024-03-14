#!/bin/bash
# NOTE: Run this script with bash shell. It will not work with sh shell.
# Example: bash wireshark_sniffer_via_mitmproxy.sh

# Logging functions
# Log levels
LOG_LEVEL_ERROR=0
LOG_LEVEL_INFO=1
LOG_LEVEL_DEBUG=2

# Set the current log level
CURRENT_LOG_LEVEL=$LOG_LEVEL_INFO

# Logging functions
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

# Function for parsing the command line arguments
find_interface_in_monitor_mode() {
  # Get all wireless interfaces
  INTERFACES=$(iwconfig 2>/dev/null | grep 'wlan' | awk '{print $1}')

  if [ -z "$INTERFACES" ]; then
    info "No wlanX interfaces found."
  else
    info "Found the following wlanX interfaces:"
    for INTERFACE in $INTERFACES; do
      info $INTERFACE
      # Check if the interface is in monitor mode
      if iwconfig $INTERFACE | grep -q "Mode:Monitor"; then
        info "$INTERFACE is in monitor mode."
        MONITOR_MODE_INTERFACE=$INTERFACE
        return
      fi
    done
    info "No wlanX interfaces are in monitor mode."
  fi
}

start_mitmproxy() {
  local MITMPROXY_OPTIONS=$1
  local MITMPROXY_AS_ROOT="" # todo fixme better structure to use sudo
  # local MITMPROXY_AS_ROOT=$2 # todo fixme better structure to use sudo

  info "Starting mitmproxy with options: $MITMPROXY_OPTIONS"
  shift
  if [ -n "$1" ]; then
    SSLKEYLOGFILE=$1
  fi
  info "SSL Key log file path set to $SSLKEYLOGFILE"
  sudo -u $USER_USERNAME setsid qterminal -e "bash -c '$MITMPROXY_AS_ROOT SSLKEYLOGFILE=$SSLKEYLOGFILE mitmproxy $MITMPROXY_OPTIONS; exec bash'" &
}

start_wireshark() {
  info "Starting wireshark and setting the tls.keylog_file..."
  if [ -n "$1" ]; then
    SSLKEYLOGFILE=$1
  fi
  info "SSL Key log file path set to $SSLKEYLOGFILE"
  nohup wireshark -o tls.keylog_file:$SSLKEYLOGFILE &>/dev/null &
}

interface_info() {
  INTERFACE=$1
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
  lshw -C network | nl

  # info "iwlist $INTERFACE scan"
  # iwlist $INTERFACE scan | nl

  info "iw $INTERFACE scan"
  sudo iw $INTERFACE scan | nl
}

# Default values
if [ "$EUID" -eq 0 ]; then
  USER_USERNAME=$SUDO_USER
  USER_HOME=$(getent passwd $SUDO_USER | cut -d: -f6)
else
  USER_USERNAME=$USER
  USER_HOME=$HOME
fi
info "Script executed as $USER_USERNAME and USER_HOME=$USER_HOME"

SSLKEYLOGFILE=$USER_HOME/Desktop/ssl_key_log.log
debug "SSL Key log file path set to $SSLKEYLOGFILE"

while [ "$#" -gt 0 ]; do
  case "$1" in
  # individual commands
  -find-intf | --find-network-interface-in-monitor-mode)
    find_interface_in_monitor_mode
    echo "Monitor mode interface: $MONITOR_MODE_INTERFACE"
    exit 0
    ;;

  -find-ssid | --find-ssid-with-scan)
    shift
    INTERFACE=$1
    shift
    network_name=$1
    shift
    lines_before=${1:-30}
    shift
    lines_after=${1:-50}
    shift
    if [ -z "$network_name" ]; then
      error "Error: Network name is required."
      exit 1
    fi
    debug "Scanning for network $network_name on interface $INTERFACE... with $lines_before lines before and $lines_after lines after."
    # sudo iwlist $INTERFACE scan | nl | grep -iE -B $lines_before -A $lines_after $network_name
    sudo iw $INTERFACE scan | nl | grep -iE -B $lines_before -A $lines_after $network_name
    exit 0
    ;;

  -mitmp | --mitmproxy-start)
    shift
    start_mitmproxy ""
    exit 0
    ;;

  -mitmp-insecure | --mitmproxy-start-insecure)
    shift
    start_mitmproxy "--ssl-insecure"
    exit 0
    ;;

  -reset-wlan | --reset-network-interface)
    shift
    INTERFACE=$1
    shift
    sudo ip link set $INTERFACE down
    sudo systemctl restart NetworkManager
    sudo iw dev $INTERFACE set type managed
    sudo ip link set $INTERFACE up
    exit 0
    ;;

  -ssh | --start-ssh)
    shift
    info "Starting ssh..."
    sudo systemctl start ssh
    sudo systemctl status ssh
    exit 0
    ;;

  -wlan-info | --wlan-interface-info)
    shift
    interface_info "$1"
    exit 0
    ;;

  -ws | --wireshark-start)
    shift
    start_wireshark "$1"
    exit 0
    ;;

  # combined commands
  -mitmp-insecure-ws | --mitmp-insecure-wireshark-startup)
    shift
    info "Setting up the sniffer..."
    start_mitmproxy "--ssl-insecure"
    start_wireshark "$1"
    exit 0
    ;;

  --) # end argument parsing
    shift
    break
    ;;
  -* | --*=) # unsupported flags
    error "Error: Unsupported flag $1" >&2
    exit 1
    ;;
  *) # preserve positional arguments
    PARAMS="$PARAMS $1"
    shift
    ;;

  esac

done
