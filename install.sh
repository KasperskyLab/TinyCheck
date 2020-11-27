#!/bin/bash

ifaces=()
rfaces=()
CURRENT_USER="${SUDO_USER}"
SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"

welcome_screen() {
cat << "EOF"
 _____ _               ___ _               _
/__   (_)_ __  _   _  / __\ |__   ___  ___| | __
  / /\/ | '_ \| | | |/ /  | '_ \ / _ \/ __| |/ /
 / /  | | | | | |_| / /___| | | |  __/ (__|   <
 \/   |_|_| |_|\__, \____/|_| |_|\___|\___|_|\_\
               |___/
-----

EOF
}

check_operating_system() {
   # Check that this installer is running on a
   # Debian-like operating system (for dependencies)

   echo -e "\e[39m[+] Checking operating system\e[39m"
   error="\e[91m    [✘] Need to be run on a Debian-like operating system, exiting.\e[39m"

   if [[ -f "/etc/os-release" ]]; then
       if [[ $(cat /etc/os-release | grep "ID_LIKE=debian") ]]; then
           echo -e "\e[92m    [✔] Debian-like operating system\e[39m"
       else
           echo -e "$error"
           exit 1
       fi
   else
       echo -e "$error"
       exit 1
   fi
}

check_connection() {
   # Checking internet connectivity to install
   # TinyCheck dependencies

   echo -e "\e[39m[+] Checking internet connectivity to install dependencies\e[39m"
   if nc -zw1 google.com 443; then
       echo -e "\e[92m    [✔] Internet link is connected\e[39m"
   else
       echo -e "\e[91m    [✘] No internet connection, exiting.\e[39m"
       exit 1
   fi
}

create_directory() {
    # Create the TinyCheck directory and move the whole stuff there.
    echo -e "[+] Creating TinyCheck folder under /usr/share/"
    mkdir /usr/share/tinycheck
    cp -Rf ./* /usr/share/tinycheck
}

generate_certificate() {
    # Generating SSL certificate for the backend.
    echo -e "[+] Generating SSL certificate for the backend"
    openssl req -x509 -subj '/CN=tinycheck.local/O=TinyCheck Backend' -newkey rsa:4096 -nodes -keyout /usr/share/tinycheck/server/backend/key.pem -out /usr/share/tinycheck/server/backend/cert.pem -days 3650
}

create_services() {
    # Create services to launch the two servers.

    echo -e "\e[39m[+] Creating services\e[39m"
    
    echo -e "\e[92m    [✔] Creating frontend service\e[39m"
    cat >/lib/systemd/system/tinycheck-frontend.service <<EOL
[Unit]
Description=TinyCheck frontend service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/share/tinycheck/server/frontend/main.py
Restart=on-abort
KillMode=process

[Install]
WantedBy=multi-user.target
EOL

    echo -e "\e[92m    [✔] Creating backend service\e[39m"
    cat >/lib/systemd/system/tinycheck-backend.service <<EOL
[Unit]
Description=TinyCheck frontend service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/share/tinycheck/server/backend/main.py
Restart=on-abort
KillMode=process

[Install]
WantedBy=multi-user.target
EOL

    echo -e "\e[92m    [✔] Creating kiosk service\e[39m"
    cat >/lib/systemd/system/tinycheck-kiosk.service <<EOL
[Unit]
Description=TinyCheck Kiosk
Wants=graphical.target
After=graphical.target

[Service]
Environment=DISPLAY=:0.0
Environment=XAUTHORITY=/home/${CURRENT_USER}/.Xauthority
Type=forking
ExecStart=/bin/bash /usr/share/tinycheck/kiosk.sh
Restart=on-abort
User=${CURRENT_USER}
Group=${CURRENT_USER}

[Install]
WantedBy=graphical.target
EOL

    echo -e "\e[92m    [✔] Creating watchers service\e[39m"
    cat >/lib/systemd/system/tinycheck-watchers.service <<EOL
[Unit]
Description=TinyCheck watchers service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/share/tinycheck/server/backend/watchers.py
Restart=on-abort
KillMode=process

[Install]
WantedBy=multi-user.target
EOL

   echo -e "\e[92m    [✔] Enabling services\e[39m"
   systemctl enable tinycheck-frontend
   systemctl enable tinycheck-backend
   systemctl enable tinycheck-kiosk
   systemctl enable tinycheck-watchers
}

configure_dnsmask() {
    # Configure DNSMASQ by appending few lines to its configuration.
    # It creates a small DHCP server for one device.

    echo -e "\e[39m[+] Configuring dnsmasq\e[39m"
    echo -e "\e[92m    [✔] Changing dnsmasq configuration\e[39m"
    rand=$(head /dev/urandom | tr -dc a-z | head -c 13)

    if [[ -f "/etc/dnsmasq.conf" ]]; then
        cat >>/etc/dnsmasq.conf <<EOL

## TinyCheck configuration ##

interface=${ifaces[-1]}
dhcp-range=192.168.100.2,192.168.100.3,255.255.255.0,24h
domain=local
address=/$rand.local/192.168.100.1
EOL
    else 
        echo -e "\e[91m    [✘] /etc/dnsmasq.conf doesn't exist, configuration not updated.\e[39m"
    fi
}

configure_dhcpcd() {
    # Configure DHCPCD by appending few lines to his configuration.
    # Allows to prevent the interface to stick to wpa_supplicant config.
    
    echo -e "\e[39m[+] Configuring dhcpcd\e[39m"
    echo -e "\e[92m    [✔] Changing dhcpcd configuration\e[39m"
    if [[ -f "/etc/dhcpcd.conf" ]]; then
        cat >>/etc/dhcpcd.conf <<EOL

## TinyCheck configuration ##

interface ${ifaces[-1]}
   static ip_address=192.168.100.1/24
   nohook wpa_supplicant
EOL
    else 
        echo -e "\e[91m    [✘] /etc/dhcpcd.conf doesn't exist, configuration not updated.\e[39m"
    fi
}

update_config(){
    # Update the configuration
    sed -i "s/iface_out/${ifaces[0]}/g" /usr/share/tinycheck/config.yaml
    sed -i "s/iface_in/${ifaces[-1]}/g" /usr/share/tinycheck/config.yaml
}

change_hostname() {
   # Changing the hostname to tinycheck
   echo -e "[+] Changing the hostname to tinycheck"
   echo "tinycheck" > /etc/hostname
   sed -i 's/raspberrypi/tinycheck/g' /etc/hosts
}

install_package() {
   # Install associated packages by using aptitude.
   if [[ $1 == "dnsmasq" || $1 == "hostapd" || $1 == "tshark" || $1 == "sqlite3" || $1 == "suricata"  || $1 == "unclutter" ]]; then
       apt-get install $1 -y
   elif [[ $1 == "zeek" ]]; then
       distrib=$(cat /etc/os-release | grep -E "^ID=" | cut -d"=" -f2)
       version=$(cat /etc/os-release | grep "VERSION_ID" | cut -d"\"" -f2)
       if [[ $distrib == "debian" || $distrib == "ubuntu" ]]; then
         echo "deb http://download.opensuse.org/repositories/security:/zeek/Debian_$version/ /" > /etc/apt/sources.list.d/security:zeek.list
         wget -nv "https://download.opensuse.org/repositories/security:zeek/Debian_$version/Release.key" -O Release.key
       elif [[ $distrib == "raspbian" ]]; then
         echo "deb http://download.opensuse.org/repositories/security:/zeek/Raspbian_$version/ /" > /etc/apt/sources.list.d/security:zeek.list
         wget -nv "https://download.opensuse.org/repositories/security:zeek/Raspbian_$version/Release.key" -O Release.key
       fi
       apt-key add - < Release.key
       rm Release.key && sudo apt-get update
       apt-get install zeek -y
    elif [[ $1 == "nodejs" ]]; then
       curl -sL https://deb.nodesource.com/setup_12.x | bash
       apt-get install -y nodejs
    elif [[ $1 == "dig" ]]; then
       apt-get install -y dnsutils
   fi
}

check_dependencies() {
   # Check binary dependencies associated to the project.
   # If not installed, call install_package with the package name.
   bins=("/usr/sbin/hostapd"
         "/usr/sbin/dnsmasq"
         "/opt/zeek/bin/zeek"
         "/usr/bin/tshark"
         "/usr/bin/dig"
         "/usr/bin/suricata"
         "/usr/bin/unclutter"
         "/usr/bin/sqlite3")

   echo -e "\e[39m[+] Checking dependencies...\e[39m"
   for bin in "${bins[@]}"
   do
       if [[ -f "$bin" ]]; then
           echo -e "\e[92m    [✔] ${bin##*/} installed\e[39m"
       else
           echo -e "\e[93m    [✘] ${bin##*/} not installed, lets install it\e[39m"
           install_package ${bin##*/}
      fi
   done
   echo -e "\e[39m[+] Install NodeJS...\e[39m"
   install_package nodejs
   echo -e "\e[39m[+] Install Python packages...\e[39m"
   python3 -m pip install -r "$SCRIPT_PATH/assets/requirements.txt"
}

compile_vuejs() {
    # Compile VueJS interfaces.
    echo -e "\e[39m[+] Compiling VueJS projects"
    cd /usr/share/tinycheck/app/backend/ && npm install && npm run build
    cd /usr/share/tinycheck/app/frontend/ && npm install && npm run build
}

create_desktop() {
    # Create desktop icon to lauch TinyCheck in a browser
    echo -e "\e[39m[+] Create Desktop icon under /home/${CURRENT_USER}/Desktop\e[39m"
    cat >"/home/$CURRENT_USER/Desktop/tinycheck.desktop" <<EOL
#!/usr/bin/env xdg-open

[Desktop Entry]
Version=1.0
Type=Application
Terminal=false
Exec=chromium-browser http://localhost
Name=TinyCheck
Comment=Launcher for the TinyCheck frontend
Icon=/usr/share/tinycheck/app/frontend/src/assets/icon.png
EOL
}

cleaning() {
    # Removing some files and useless directories
    rm /usr/share/tinycheck/install.sh
    rm /usr/share/tinycheck/README.md
    rm /usr/share/tinycheck/LICENSE.txt
    rm /usr/share/tinycheck/NOTICE.txt
    rm -rf /usr/share/tinycheck/assets/

    # Disabling the suricata service
    systemctl disable suricata.service &> /dev/null

    # Removing some useless dependencies.
    sudo apt autoremove -y
}

check_wlan_interfaces() {
   # Check the presence of two wireless interfaces by using rfkill.
   # Check if they are recognized by ifconfig, if not unblock them with rfkill.
   echo -e "\e[39m[+] Checking your wireless interfaces"

   for iface in $(ifconfig | grep -oE wlan[0-9]); do ifaces+=("$iface"); done
   for iface in $(rfkill list | grep -oE phy[0-9]); do rfaces+=("$iface"); done

   if [[ "${#ifaces[@]}" > 1 ]]; then
       echo -e "\e[92m    [✔] Two interfaces detected, lets continue!\e[39m"
       if [[ "${#ifaces[@]}" < 1 ]]; then
               for iface in rfaces; do rfkill unblock "$iface"; done
       fi
   else
       echo -e "\e[91m    [✘] Two wireless interfaces are required."
       echo -e "              Please, plug a WiFi USB dongle and retry the install, exiting.\e[39m"
       exit
   fi
}

create_database() {
    # Create the database under /usr/share/tinycheck/tinycheck.sqlite
    # This base will be provisioned in IOCs by the watchers
    sqlite3 "/usr/share/tinycheck/tinycheck.sqlite3" < "$SCRIPT_PATH/assets/scheme.sql"
}

change_configs() {
    # Disable the autorun dialog from pcmanfm
    if [[ -f "/home/$CURRENT_USER/.config/pcmanfm/LXDE-pi/pcmanfm.conf" ]]; then
        sed -i 's/autorun=1/autorun=0/g' "/home/$CURRENT_USER/.config/pcmanfm/LXDE-pi/pcmanfm.conf"
    fi
    # Disable the .desktop script popup
    if [[ -f "/home/$CURRENT_USER/.config/libfm/libfm.conf" ]]; then
        sed -i 's/quick_exec=0/quick_exec=1/g' "/home/$CURRENT_USER/.config/libfm/libfm.conf"
    fi
}

feeding_iocs() {
    echo -e "\e[39m[+] Feeding your TinyCheck instance with fresh IOCs and whitelist."
    python3 /usr/share/tinycheck/server/backend/watchers.py
}

reboot_box() {
    echo -e "\e[92m[+] The system is going to reboot\e[39m"
    sleep 5
    reboot
}

if [[ $EUID -ne 0 ]]; then
    echo "This must be run as root. Type in 'sudo bash $0' to run."
	exit 1
else
    welcome_screen
    check_operating_system
    check_connection
    check_wlan_interfaces
    create_directory
    check_dependencies
    configure_dnsmask
    configure_dhcpcd
    update_config
    change_hostname
    generate_certificate
    compile_vuejs
    create_database
    create_services
    create_desktop
    change_configs
    feeding_iocs
    cleaning
    reboot_box
fi
