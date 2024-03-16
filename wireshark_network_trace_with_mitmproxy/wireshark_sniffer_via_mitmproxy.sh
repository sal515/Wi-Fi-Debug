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

PRESERVE_GREP_COLOR="--color=always"
SSID_SEARCH_GREP_DEFAULT_LINES_BEFORE=30
SSID_SEARCH_GREP_DEFAULT_LINES_AFTER=50

while [ "$#" -gt 0 ]; do
  case "$1" in
  # individual commands
  -ssid-find | --ssid-find-by-scan)
    shift
    INTERFACE=$1
    shift
    network_name_pattern=$1
    shift
    lines_before=${1:-$SSID_SEARCH_GREP_DEFAULT_LINES_BEFORE}
    shift
    lines_after=${1:-$SSID_SEARCH_GREP_DEFAULT_LINES_AFTER}
    shift

    if [ -z "$network_name_pattern" ]; then
      error "Error: Network name is required."
      exit 1
    fi

    debug "Scanning for network $network_name_pattern on interface $INTERFACE... with $lines_before lines before and $lines_after lines after."

    SCAN_OUTPUT=$(sudo iw "$INTERFACE" scan)
    debug "SCAN_OUTPUT: $SCAN_OUTPUT"

    NETWORK_NAME_BLOCK=$(echo "$SCAN_OUTPUT" | grep $PRESERVE_GREP_COLOR -iE -B 5 -A 5 "$network_name_pattern" | grep $PRESERVE_GREP_COLOR -iE -B 5 -A 5 "SSID")
    debug "NETWORK_NAME_BLOCK: $NETWORK_NAME_BLOCK"

    NETWORK_NAME=$(echo "$NETWORK_NAME_BLOCK" | grep $PRESERVE_GREP_COLOR -oiE "SSID.*" | awk '{print $2}')

    CHANNEL=$(echo "$NETWORK_NAME_BLOCK" | grep $PRESERVE_GREP_COLOR -oiE "channel.*" | awk '{print $2}')

    if [ -z "$CHANNEL" ] || [ -z "$NETWORK_NAME" ]; then
      error "Error: Network $network_name_pattern not found or invalid channel."
      exit 1
    fi

    info "Network with SSID: $NETWORK_NAME found on channel: $CHANNEL"
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

  -ssh | --ssh-start)
    shift
    info "Starting ssh..."
    sudo systemctl start ssh
    sudo systemctl status ssh
    exit 0
    ;;

  -wlan-find | --wlan-find-interface-in-monitor-mode)
    find_interface_in_monitor_mode
    echo "Monitor mode interface: $MONITOR_MODE_INTERFACE"
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
