#!/bin/bash
# NOTE: Run this script with bash shell. It will not work with sh shell.
# Example: bash wireshark_sniffer_via_mitmproxy.sh

# include the other bash script with the function definitions

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
FUNCTION_DEFINITIONS_PATH="${SCRIPT_DIR}/wifi_debug_function_definitions.sh"
if [ ! -f "$FUNCTION_DEFINITIONS_PATH" ]; then
  echo "Error: File not found: $FUNCTION_DEFINITIONS_PATH"
  exit 1
fi
source $FUNCTION_DEFINITIONS_PATH

# CURRENT_LOG_LEVEL=$LOG_LEVEL_DEBUG
CURRENT_LOG_LEVEL=$LOG_LEVEL_INFO

create_symbolic_link

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

  -ssh | --ssh-start)
    shift
    info "Starting ssh..."
    start_ssh_service
    exit 0
    ;;

  -ssh-service | --ssh-service-status)
    shift
    info "Enable ssh service..."
    enable_ssh_service
    exit 0
    ;;

  -ssid-find | --ssid-find-by-scan)
    shift
    interface=$1
    shift
    ssid_name=$1
    shift
    find_network $interface $ssid_name
    info "SSID: $SSID_NAME Channel: $SSID_CHANNEL"
    exit 0
    ;;

  -wlan-find | --wlan-find-interface-in-monitor-mode)
    find_wlan_interface_in_monitor_mode
    info "wlan interface in Monitor mode: $MONITOR_MODE_INTERFACE"
    exit 0
    ;;

  -wlan-info | --wlan-info-interface)
    shift
    interface_info "$1"
    exit 0
    ;;

  -wlan-reset | --wlan-reset-interface)
    shift
    INTERFACE=$1
    shift
    sudo ip link set $INTERFACE down
    sudo systemctl restart NetworkManager
    sudo iw dev $INTERFACE set type managed
    sudo ip link set $INTERFACE up
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
