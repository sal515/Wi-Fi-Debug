# Wifi Debug Project

# Hardware

1. Raspberry Pi with Power Supply - Tested with RPi 4B
2. (Optional) External USB WiFi adapter such as Alfa AWUS036AXML,
   if the internal wifi adapter is not capable of monitor mode

# Tools

1.  Linux OS installed on Raspberry Pi that supports the external USB WiFi adapter
    (e.g., Raspberry Pi OS, Ubuntu, etc.)
2.  vscode [download link](https://code.visualstudio.com/download) with recommended plugins:

    2.1. C/C++ & C/C++ Extension Pack  
    2.2. Python & Python Debugger & Pylint & Pylance & isort (from Microsoft)  
    2.3. CMake & CMake tools  
    2.4. Black Formatter - Python  
    2.5. Python Environment Manager  
    2.6. GitHub Co-Pilot & Chat (if available)  
    2.7. shell-format  
    2.8. Prettier - Code formatter  
    2.9. GitLens

3.  git

# General RPI Setup

1. Install RPi OS on the Raspberry Pi with the **External USB WiFi adapter Disconnected**

   Raspberry Pi Imager with OS Customization tool can be used to install the OS on the RPI:  
   [Link](https://www.raspberrypi.com/software/)

   For headless setup use the **OS Customization tool** to provide the following:

   1. Hostname
   2. Username & Password
   3. SSID & SSID_Password
   4. Enable SSH

   ![rpi_imager_os_customization_tool_page_1](https://www.raspberrypi.com/documentation/computers/images/imager/os-customisation-general.png)
   ![rpi_imager_os_customization_tool_page_2](https://www.raspberrypi.com/documentation/computers/images/imager/os-customisation-services.png)

2. Find the IP address of the RPI using the router's admin page or other methods

3. SSH into the RPI using vscode with the IP address of RPi  
   SSH with vscode tutorial [here](https://code.visualstudio.com/docs/remote/ssh-tutorial)

   ![SSH Option button in vscode](https://code.visualstudio.com/assets/docs/remote/ssh-tutorial/remote-status-bar.png)
   ![Remote-SSH: Connect to Host... option](https://code.visualstudio.com/assets/docs/remote/ssh-tutorial/remote-ssh-commands.png)

4. Install git:
   `sudo apt-get install git`
5. Clone or download this repository from GitHub:
   `git clone git@github.com:sal515/Wi-Fi-Debug.git`

   (Optional) Update ~/.bashrc or ~/.profile to include GitHub ssh keys

   ```
       # Geneate SSH keys on the RPI
       ssh-keygen -t ed25519 "salman@email.com"
       # Add the generated ~/.ssh/<name>.pub to the GitHub SSH Keys list

       # Update the ~/.bashrc or ~/.profile based on the type of terminal used
       # Enables the ssh-agent and add the ssh key to the agent for new terminals

       echo "sourced: .bashrc (non-login shell)"
       echo "enable ssh-agent and add sal515 github key"
       eval "$(ssh-agent -s)"
       ssh-add ~/.ssh/sal515_github

   ```

6.

# How to use the wifi_debug_rpi_commands.sh script

# USB WiFi Adapter Info

1. Alfa AWUS036AXML [Link](https://www.alfa.com.tw/products/awus036axml?variant=39754360684616)
   - Chipset: MediaTek MT7921AUN
   - IEEE 802.11 standards: a/b/g/n/ac/ax (Tri-band)
   - Bluetooth: 5.2
   - Monitor Mode: Supported
   - Power consumption: 2.7 Watts (max.) with 5V
   - OS Support: RPi OS [version: **bookworm**] has the driver pre-installed
