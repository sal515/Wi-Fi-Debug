#!/bin/bash
# NOTE: Run this script with bash shell. It will NOT work with sh shell.
# Example: bash wifi_debug/wifi_debug_rpi_commands.sh

SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
SCRIPT_FUNCTION_DEFINITIONS_PATH="${SCRIPT_DIR}/wifi_debug_function_definitions.sh"
if [ ! -f "$SCRIPT_FUNCTION_DEFINITIONS_PATH" ]; then
    echo "Error: File not found: $SCRIPT_FUNCTION_DEFINITIONS_PATH"
    exit 1
fi
source $SCRIPT_FUNCTION_DEFINITIONS_PATH

# TODO FIXME
# CURRENT_LOG_LEVEL=$LOG_LEVEL_DEBUG
CURRENT_LOG_LEVEL=$LOG_LEVEL_INFO

SYMBOL="rpidbg"

create_symbolic_link "$SYMBOL" &&
    info "[$SYMBOL] symbol for this script is available system wide" ||
    error "Error: Failed to create symbolic link"

# Default values
if [ "$EUID" -eq 0 ]; then
    USER_USERNAME=$SUDO_USER
    USER_HOME=$(getent passwd $SUDO_USER | cut -d: -f6)
else
    USER_USERNAME=$USER
    USER_HOME=$HOME
fi
info "Script executed as $USER_USERNAME and USER_HOME=$USER_HOME"

RPI_SHARE="rpi_share"
PATH_TO_RPI_SHARE_DIR=$USER_HOME/"$RPI_SHARE"

SSLKEYLOGFILE=$PATH_TO_RPI_SHARE_DIR/ssl_key_log.log
debug "SSL Key log file path set to $SSLKEYLOGFILE"

