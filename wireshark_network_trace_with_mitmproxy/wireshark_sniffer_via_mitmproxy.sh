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

  -ws | --wireshark-start)
    shift
    start_wireshark "$1"
    exit 0
    ;;

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
