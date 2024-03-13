#!/bin/bash

# If the first argument is not provided, use the default value
SSLKEYLOGFILE=${1:-~/Desktop/ssl_key_log.log}


# Parse command line arguments
while (( "$#" )); do
  case "$1" in
    --sslkeylogfile)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        SSLKEYLOGFILE=$2
        shift 2
      else
        echo "Error: Argument for $1 is missing" >&2
        exit 1
      fi
      ;;
    --) # end argument parsing
      shift
      break
      ;;
    -*|--*=) # unsupported flags
      echo "Error: Unsupported flag $1" >&2
      exit 1
      ;;
    *) # preserve positional arguments
      PARAMS="$PARAMS $1"
      shift
      ;;
  esac
done


echo "Wireshark Sniffer Environment Setup Script..."
echo "Requires: Wifi Adapter, Kali Linux (other debian OSes too), Wireshark, mitmproxy, and SSLKEYLOGFILE environment variable setup."

# Create a new terminal window in Kali Linux and run the following command: sudo SSLKEYLOGFILE=~/Desktop/ssl_key_log.log  mitmproxy --ssl-insecure
# qterminal -e "bash -c 'sudo SSLKEYLOGFILE=~/Desktop/ssl_key_log.log mitmproxy --ssl-insecure; exec bash'"

# Create a new terminal window in Kali Linux and run the following command: sudo SSLKEYLOGFILE=~/Desktop/ssl_key_log.log  mitmproxy --ssl-insecure
setsid qterminal -e "bash -c 'sudo SSLKEYLOGFILE=$SSLKEYLOGFILE mitmproxy --ssl-insecure; exec bash'" &