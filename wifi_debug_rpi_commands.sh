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

while [ "$#" -gt 0 ]; do
    case "$1" in
    -rpi-ssh-key | --rpi-ssh-key-set)
        # Example usage: rpidbg -rpi-ssh-key-set "SSH_PUBLIC_KEY"
        shift
        ssh_public_key="$1"
        [ -z "$ssh_public_key" ] && error "Error: SSH public key is empty" && exit 1
        ssh_authorized_keys_filepath="/home/$USER_USERNAME/.ssh/authorized_keys"
        sshd_config_filepath="/etc/ssh/sshd_config"
        setup_ssh_pub_key_usage_and_append_pub_ssh_key "$ssh_authorized_keys_filepath" "$sshd_config_filepath" "$ssh_public_key"
        ;;

    -rpi-wlan-conn-info | --rpi-show-wlan-connection-related_info_show)
        # Example usage: rpidbg -rpi-wlan-conn-info
        shift
        rpi_wlan_interface_info
        ;;

    -rpi-wlan-set-mon-ch | --rpi-wlan-set-monitor-mode-and-channel)
        # Example usage: rpidbg -rpi-wlan-set-mon-ch "wlan1" "tp.*link"
        shift
        wlan_interface=$1
        shift
        ssid_name_pattern=$1
        shift
        [ -z "$wlan_interface" ] && error "Error: WLAN interface is empty" && exit 1
        if ! which airodump-ng >/dev/null; then
            read -p "airodump-ng is not installed. Do you want to install it? (y/n) " -n 1 -r
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                sudo apt-get install aircrack-ng
            else
                error "Error: airodump-ng is required to set the monitor mode"
                exit 1
            fi
        fi

        find_ssid_channel_using_airodump_ng $wlan_interface $ssid_name_pattern $SCRIPT_DIR
        info "SSID: "$SSID" Channel: "$CHANNEL""
        sleep 3
        setup_interface_in_monitor_mode $wlan_interface $CHANNEL

        # ask the user if they want to install tshark?
        if ! which tshark >/dev/null; then
            read -p "tshark is not installed. Do you want to install it? (y/n) " -n 1 -r
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                sudo apt-get install tshark
            else
                error "Error: tshark is required to capture packets"
                exit 1
            fi
        fi
        ;;

    -rpi-wlan-discon | --rpi-wlan-disconnect)
        # Example usage: rpidbg -rpi-wlan-disconnect "wlan0"
        shift
        wlan_interface=$1
        [ -z "$wlan_interface" ] && error "Error: WLAN interface is empty" && exit 1
        nmcli d status
        info "Disconnecting the WLAN interface: $wlan_interface"
        sudo nmcli device disconnect $wlan_interface
        info "Disconnected the WLAN interface: $wlan_interface"
        nmcli d status
        ;;

    -rpi-samba-setup | --rpi-samba-file-share-setup)
        # Example usage: rpidbg -rpi-samba-setup
        # In windows add a mapped drive as \\<IP address of RPI>\<shared_dir_name>
        # Example: \\192.168.2.246\rpi_share
        shift
        if [ ! -d "$PATH_TO_RPI_SHARE_DIR" ]; then
            mkdir $PATH_TO_RPI_SHARE_DIR
            sudo chmod 0777 $PATH_TO_RPI_SHARE_DIR
        fi
        samba_conf_path="/etc/samba/smb.conf"

        info "Setting up the Samba file share for the directory: $PATH_TO_RPI_SHARE_DIR"
        dpkg -l | grep -qw samba || {
            error "Samba is not installed, installing..."
            sudo apt update && sudo apt install -y samba
        }
        dpkg -l | grep -qw samba-common-bin || {
            error "samba-common-bin is not installed, installing..."
            sudo apt update && sudo apt install -y samba-common-bin
        }

        comment_out_conf_line="map to guest = bad user"
        if grep -q "^[\t ]*$comment_out_conf_line" $samba_conf_path; then
            sudo sed -i "/^[\t ]*$comment_out_conf_line/s/^/#/" $samba_conf_path
            info "The line '$comment_out_conf_line' has been commented out."
        elif grep -q "^#[\t ]*$comment_out_conf_line" $samba_conf_path; then
            info "The line '$comment_out_conf_line' is already commented out."
        else
            info "'$comment_out_conf_line' - value was not found or could not be updated - please review $samba_conf_path" && exit 1
        fi

        grep -q "\[${RPI_SHARE}\]" $samba_conf_path ||
            echo -e "\n\n[${RPI_SHARE}]\n   path = ${PATH_TO_RPI_SHARE_DIR}\n   writeable = yes\n   create mask = 0777\n   directory mask = 0777\n   public = no\n   guest ok = no\n   valid users = "$USER_USERNAME"" |
            sudo tee -a $samba_conf_path >/dev/null
        sudo smbpasswd -a $USER_USERNAME
        sudo systemctl restart smbd nmbd

        # Test - Samba with localhost
        # sudo apt update
        # testparam  $samba_conf_path
        # sudo apt install smbclient
        # smbclient //localhost/"$RPI_SHARE" -U $USER_USERNAME
        ;;

        # TODO FIXME: Set the priority of the connections (wlan0 vs eth0 or others)
        # Show the connection available
        # nmcli c show
        # Show details of the connection
        # nmcli c show "Wired connection 1"
        # nmcli c show "TP-Link_2293_RPI_BUILT_IN"
        # Set the connection priority - Higher number is higher priority for autoconnect-priority during startup
        # sudo nmcli c modify "Wired connection 1" connection.autoconnect-priority 1
        # -rpi-set-conn-prio | --rpi-wlan-connection-create-set-to-autostart-linked-to-wlan-interface)

        # TODO FIXME WIP - NOT TESTED - DO NOT DELETE - Update the network Connection using nmcli - supported after RPI Debian GNU/Linux 12 (bookworm)
        # TODO List:
        # 1. Identify the WLAN that is external adatper
        # 2. Provide the WLAN interfaces as an option to the user to choose from
        # 3. Create a new connection for the SSID with the selected WLAN interface
        # 4. Modify the new connection to use WPA PSK and provide Password in the file not CLI for security reasons
        # 5. Set the connection to autoconnect and make the file 700 executable
        # 6. Remove the preconfigured connection from the undesired WLAN interface by setting it to autoconnect no
        # -rpi-wlan-conn-setup | --rpi-wlan-connection-create-set-to-autostart-linked-to-wlan-interface)
        # ls -lah /etc/NetworkManager/system-connections/
        # nmcli c show
        # nmcli c show "preconfigured"
        # sudo nmcli c add type wifi con-name "TP-Link_2293_RPI_BUILT_IN" ifname wlan0 ssid "TP-Link_2293"
        # sudo nmcli c modify "TP-Link_2293_RPI_BUILT_IN" wifi-sec.key-mgmt wpa-psk
        # ask to update the PSK in the nmconnection file?
        # sudo nano /etc/NetworkManager/system-connections/TP-Link_2293_RPI_BUILT_IN.nmconnection
        # sudo chmod 700 "/etc/NetworkManager/system-connections/TP-Link_2293_RPI_BUILT_IN.nmconnection"
        # sudo nmcli c mod "TP-Link_2293_RPI_BUILT_IN" autoconnect yes
        # ls -lah /etc/NetworkManager/system-connections/
        # nmcli c show "TP-Link_2293_RPI_BUILT_IN"
        # sudo nmcli c mod "preconfigured" autoconnect no
        #   ;;

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
