#!/bin/bash
# NOTE: Run this script with bash shell. It will NOT work with sh shell.
# Example: bash wifi_debug/wifi_debug_commands.sh

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

SYMBOL="wifidbg"

create_symbolic_link $SYMBOL &&
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

while [ "$#" -gt 0 ]; do
  case "$1" in
  # individual commands
  -mitmp | --mitmproxy-start)
    # Example usage: wifidbg -mitmp "insecure" 8888 true /path/to/ssl_key_log.log
    shift
    [ "$1" = "insecure" ] && mitmproxy_ssl_insecure_option="--ssl-insecure" ||
      mitmproxy_ssl_insecure_option=${1:-""}
    listen_port=${2:-"8888"}
    use_cli_mode=${3:-"false"}
    ssl_key_log_file=${4:-$SSLKEYLOGFILE}

    debug "mitmproxy_ssl_insecure_option: $mitmproxy_ssl_insecure_option, use_cli_mode: $use_cli_mode, ssl_key_log_file: $ssl_key_log_file"

    if ! which mitmproxy >/dev/null; then
      read -p "mitmproxy is not installed. Do you want to install it? (y/n) " -n 1 -r
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt-get install mitmproxy
      else
        error "Error: mitmproxy is required"
        exit 1
      fi
    fi

    info "Starting mitmproxy with options: $mitmproxy_ssl_insecure_option SSLKeyFile: $ssl_key_log_file USER: $USER_USERNAME"
    start_mitmproxy $USER_USERNAME $ssl_key_log_file $mitmproxy_ssl_insecure_option $use_cli_mode $listen_port
    exit 0
    ;;

  -mitmp-revp | --mitmproxy-reverseproxy-start)
    # Example usage: wifidbg -mitmp-revp 8888 192.168.0.232 5003 "insecure"
    # NOTE: The client needs to trust the mitmproxy certificate: ~/.mitmproxy/mitmproxy-ca-cert.pem
    # NOTE: The mitmproxy does not need to be provided with the Upstream server certificate if "--ssl-insecure" is used;
    #       This skips SSL verification of the upstream server
    # Instructions: How to use this cmd and mitmproxy in reverse proxy mode for HTTPs to decrypt TLS packets:
    # 1. Install the ~/.mitmproxy/mitmproxy-ca-cert.pem certificate on the Client
    # 2. Set the Destination IP Port in the Client towards the mitmproxy reverse proxy
    # 3. Start the mitmproxy in reverse proxy mode using this command, an example is provided above
    # 3.a. The mitmproxy will listen on the specified port and forward the traffic from the client to the destination IP and Port of the Upstream Server
    # 3.b. The mitmproxy will store the SSL session keys to the ssl_key_log_file that can be eventually used by Wireshark to decrypt the TLS packets
    # 4. If the upstream server is a dev server, start the server
    # 5. Start Wireshark packet capture after setting the tls.keylog_file to the ssl_key_log_file [can be done from preferences]
    #    Capture with tshark on RPI and pipe to Wireshark Windows:
    #    ssh -i "C:\Users\<usr>\.ssh\private_key_gen_with_sshkeygen" -p <Port> <usr>@<ip> "sudo tshark -i wlan<X> -w - -f 'not port 22'" | "C:\Program Files\Wireshark\Wireshark.exe" -k -i -
    #    Wireshark Display filter to ignore 802.11 packets: !(_ws.col.protocol == "802.11")
    # 6. Start the client and send the request to the mitmproxy reverse proxy
    # 7. Wireshark will be able to decrypt the TLS packet after the capture session is stored as pcapng and reopened for the decryption to run
    #    Ref: Client request "c define" example: [The following RAW HTTPs request was sent from client using socket]
    #                        #define DATA "GET / HTTP/1.1\r\n" \
    #                                "Host: 192.168.0.232:8888\r\n" \
    #                                "Content-Type: text/plain\r\n" \
    #                                "Content-Length: 5\r\n" \
    #                                "\r\n" \
    #                                "hello"
    shift
    listen_port=${1:-"8888"}
    dst_ip_address="$2"
    dst_port=$3
    [ "$4" = "insecure" ] && mitmproxy_ssl_insecure_option="--ssl-insecure" ||
      mitmproxy_ssl_insecure_option=${1:-""}
    ssl_key_log_file=${5:-$SSLKEYLOGFILE}
    debug "mitmproxy_ssl_insecure_option: $mitmproxy_ssl_insecure_option, dst_ip_address: $dst_ip_address, dst_port: $dst_port, ssl_key_log_file: $ssl_key_log_file"

    if ! which mitmproxy >/dev/null; then
      read -p "mitmproxy is not installed. Do you want to install it? (y/n) " -n 1 -r
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo apt-get install mitmproxy
      else
        error "Error: mitmproxy is required"
        exit 1
      fi
    fi
    # Exporting the SSL Session Key to a file, to be used for TLS application data decryption
    export SSLKEYLOGFILE=$ssl_key_log_file
    info "Verify the SSLKEYLOGFILE env variable is set"
    env | grep "SSLKEYLOGFILE"
    sleep 2
    mitmproxy -v --listen-port $listen_port --mode reverse:https://$dst_ip_address:$dst_port $mitmproxy_ssl_insecure_option
    exit 0
    ;;

  -ssh | --ssh-start)
    # Example usage: wifidbg -ssh-start
    shift
    info "Starting ssh..."
    start_ssh_service
    exit 0
    ;;

  -ssh-service | --ssh-service-status)
    # Example usage: wifidbg -ssh-service
    shift
    info "Enable ssh service..."
    enable_ssh_service
    exit 0
    ;;

  -ssid-find | --ssid-find-by-scan)
    # Example usage: wifidbg -ssid-find wlan0 "tp.*link"
    shift
    interface=$1
    shift
    ssid_name_pattern=$1
    shift
    [ -z "$interface" ] && error "Error: Interface name is empty" && exit 1
    [ -z "$ssid_name" ] && error "Error: SSID name is empty" && exit 1

    find_ssid_channel_using_airodump_ng $interface $ssid_name_pattern $SCRIPT_DIR
    info "SSID: $SSID Channel: $CHANNEL"
    exit 0
    ;;

  -wlan-find | --wlan-find-interface-in-monitor-mode)
    # Example usage: wifidbg -wlan-find
    shift
    find_wlan_interface_in_monitor_mode
    if [ "$?" -eq $ERROR_CODE_NOT_FOUND ]; then
      info "No wlan interface found in Monitor mode"
      exit 1
    elif [ "$?" -eq $ERROR_CODE_NO_DEVICE ]; then
      info "No wlan interfaces found"
      exit 1
    fi
    info "wlan interface found in Monitor mode: $MONITOR_MODE_INTERFACE"
    exit 0
    ;;

  -wlan-info | --wlan-info-interface)
    # Example usage: wifidbg -wlan-info wlan0
    shift
    interface=${1:-"wlan0"}
    shift
    wlan_all_info $interface
    exit 0
    ;;

  -wlan-reset | --wlan-reset-interface)
    # Example usage: wifidbg -wlan-reset wlan0 monitor 4
    shift
    interface=${1:-"wlan0"}
    shift
    mode=${1:-"monitor"}
    shift
    channel=$1
    shift
    configure_wlan_interface $interface $mode $channel
    wlan_iw_info $interface
    exit 0
    ;;

  -ws | --wireshark-start)
    # Example usage: wifidbg -ws /path/to/ssl_key_log.log
    shift
    ssl_key_log_file=${1:-$SSLKEYLOGFILE}
    shift
    info "Starting wireshark and setting the tls.keylog_file=$ssl_key_log_file"
    start_wireshark "$ssl_key_log_file"
    exit 0
    ;;

  -ws-bkup | --wireshark-start-backup)
    # Example usage: wifidbg -ws-bkup "80211_tcpip" "/path/to/backup_dir"
    shift
    profile_name=$1
    [ -z "$profile_name" ] && error "Error: Profile name is empty" && exit 1
    shift
    backup_path_dir=$1
    [ -z "$backup_path_dir" ] && error "Error: Backup path directory is empty" && exit 1
    shift
    backup_wireshark_config "$USER_HOME" $profile_name $backup_path_dir
    exit 0
    ;;

  # combined commands
  -setup | --setup-with-default)
    # Example usage: wifidbg -setup wlan0 "tp.*link" "insecure"
    shift
    interface=$1
    [ -z "$interface" ] && error "Error: Interface name is empty" && exit 1
    shift
    ssid_name_pattern=$1
    [ -z "$ssid_name" ] && error "Error: SSID name is empty" && exit 1
    shift
    [ "$1" = "insecure" ] && mitmproxy_ssl_insecure_option="--ssl-insecure" ||
      mitmproxy_ssl_insecure_option=${1:-""}
    shift
    ssl_key_log_file=${1:-$SSLKEYLOGFILE}
    shift

    find_ssid_channel_using_airodump_ng $interface $ssid_name_pattern $SCRIPT_DIR
    info "SSID: $SSID Channel: $CHANNEL"

    sleep 3

    info "Setting up the sniffer environment..."
    read -p "Do you want to set the channel to $CHANNEL used by SSID: $SSID? (y/n) " -n 1 -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      setup_interface_in_monitor_mode $interface $CHANNEL
    else
      read -p "Enter the channel number for SSID: $ssid_name: " -n 2 -r
      MANUAL_SSID_CHANNEL=$REPLY
      setup_interface_in_monitor_mode $interface $MANUAL_SSID_CHANNEL
    fi

    sleep 3
    info "Starting mitmproxy with options: $mitmproxy_ssl_insecure_option SSLKeyFile:$ssl_key_log_file USER: $USER_USERNAME"
    start_mitmproxy $USER_USERNAME $ssl_key_log_file $mitmproxy_ssl_insecure_option

    sleep 3
    info "Starting wireshark and setting the tls.keylog_file=$ssl_key_log_file"
    start_wireshark "$ssl_key_log_file"
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
