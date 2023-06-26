#!/bin/bash

CURRENT_USER="${SUDO_USER}"
SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"
HOST="$( hostname )"
IFACES="$( ip a s | grep -Eo '[a-z0-9]{4,15}\: ' | grep -oE [a-z0-9]+ )"
IFACE_OUT=""
IFACE_IN=""
LOCALES=(en fr cat es ru pt de it)

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
       if [[ $(cat /etc/os-release | grep -e "ID_LIKE=\"\?debian" -e "ID=debian") ]]; then
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

set_userlang() {
    # Set the user language.
    echo -e "\e[39m[+] Setting the user language...\e[39m"
    printf -v joined '%s/' "${LOCALES[@]}"
    echo -n "    Please choose a language for the reports and the user interface (${joined%/}): "
    read lang

    if [[ " ${LOCALES[@]} " =~ " ${lang} " ]]; then
        sed -i "s/userlang/${lang}/g" /usr/share/tinycheck/config.yaml
        echo -e "\e[92m    [✔] User language settled!\e[39m"
    else
        echo -e "\e[91m    [✘] You must choose between the languages proposed, let's retry.\e[39m"
        set_userlang
    fi
}

set_credentials() {
    # Set the credentials to access to the backend.
    echo -e "\e[39m[+] Setting the backend credentials...\e[39m"
    echo -n "    Please choose a username for TinyCheck's backend: "
    read login
    echo -n "    Please choose a password for TinyCheck's backend: "
    read -s password1
    echo ""
    echo -n "    Please confirm the password: "
    read -s password2
    echo ""

    if [ "$password1" == "$password2" ]; then
        password=$(echo -n "$password1" | sha256sum | cut -d" " -f1)
        sed -i "s/userlogin/$login/g" /usr/share/tinycheck/config.yaml
        sed -i "s/userpassword/$password/g" /usr/share/tinycheck/config.yaml
        echo -e "\e[92m    [✔] Credentials saved successfully!\e[39m"
    else
        echo -e "\e[91m    [✘] The passwords aren't equal, please retry.\e[39m"
        set_credentials
    fi
}

set_kioskmode() {
    echo -n "[?] Do you want to start TinyCheck in fullscreen during the system startup (aka. Kiosk mode)? [Yes/No] "
    read answer
    if [[ "$answer" =~ ^([yY][eE][sS]|[yY])$ ]]
    then
        sed -i "s/kioskmode/true/g" /usr/share/tinycheck/config.yaml
        sed -i "s/hidemouse/true/g" /usr/share/tinycheck/config.yaml
        sed -i "s/quitoption/true/g" /usr/share/tinycheck/config.yaml
        echo -e "\e[92m    [✔] TinyCheck settled in kiosk mode\e[39m"
    else
        sed -i "s/kioskmode/false/g" /usr/share/tinycheck/config.yaml
        sed -i "s/hidemouse/false/g" /usr/share/tinycheck/config.yaml
        sed -i "s/quitoption/false/g" /usr/share/tinycheck/config.yaml
        echo -e "\e[92m    [✔] TinyCheck settled in default mode, use the desktop icon to launch it.\e[39m"
    fi
}

set_update() {
    echo -n "[?] Do you want to be able to update TinyCheck from the frontend interface? [Yes/No] "
    read answer
    if [[ "$answer" =~ ^([yY][eE][sS]|[yY])$ ]]
    then
        sed -i "s/updateoption/true/g" /usr/share/tinycheck/config.yaml
        echo -e "\e[92m    [✔] You'll be able to update it from the frontend!\e[39m"
    else
        sed -i "s/updateoption/false/g" /usr/share/tinycheck/config.yaml
        echo -e "\e[92m    [✔] You'll need to pass by the console script to update TinyCheck.\e[39m"
    fi
}

create_directory() {
    # Create the TinyCheck directory and move the whole stuff there.
    echo -e "[+] Creating TinyCheck folder under /usr/share/"
    mkdir /usr/share/tinycheck
    cp -Rf ./* /usr/share/tinycheck
}

get_version() {
    git tag | tail -n 1 | xargs echo -n > /usr/share/tinycheck/VERSION
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
Description=TinyCheck backend service

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
   systemctl enable tinycheck-frontend &> /dev/null
   systemctl enable tinycheck-backend &> /dev/null
   systemctl enable tinycheck-kiosk &> /dev/null
   systemctl enable tinycheck-watchers &> /dev/null
}

configure_dnsmask() {
    # Configure DNSMASQ by appending few lines to its configuration.
    # It creates a small DHCP server for one device.

    echo -e "\e[39m[+] Configuring dnsmasq\e[39m"
    echo -e "\e[92m    [✔] Changing dnsmasq configuration\e[39m"

    if [[ -f "/etc/dnsmasq.conf" ]]; then
        cat >>/etc/dnsmasq.conf <<EOL

## TinyCheck configuration ##

interface=${IFACE_IN}
dhcp-range=192.168.100.2,192.168.100.3,255.255.255.0,24h
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

interface ${IFACE_IN}
   static ip_address=192.168.100.1/24
   nohook wpa_supplicant
EOL
    else
        echo -e "\e[91m    [✘] /etc/dhcpcd.conf doesn't exist, configuration not updated.\e[39m"
    fi
}

update_config(){
    # Update the configuration
    sed -i "s/iface_out/${IFACE_OUT}/g" /usr/share/tinycheck/config.yaml
    sed -i "s/iface_in/${IFACE_IN}/g" /usr/share/tinycheck/config.yaml
}

change_hostname() {
   # Changing the hostname to tinycheck
   echo -e "[+] Changing the hostname to tinycheck"
   echo "tinycheck" > /etc/hostname
   sed -i "s/$HOST/tinycheck/g" /etc/hosts

   # Adding tinycheck.local to the /etc/hosts.
   echo "127.0.0.1  tinycheck.local" >> /etc/hosts
}

install_package() {
   # Install associated packages by using aptitude.
   if [[ $1 == "dnsmasq" || $1 == "hostapd" || $1 == "tshark" || $1 == "sqlite3" || $1 == "unclutter" || $1 == "swig" || $1 == "curl" ]]; then

       apt-get install $1 -y
   elif [[ $1 == "suricata" ]];then 
       add-apt-repository ppa:oisf/suricata-stable
       apt-get install suricata -y
   elif [[ $1 == "zeek" ]]; then
       distrib=$(cat /etc/os-release | grep -E "^ID=" | cut -d"=" -f2)
       version=$(cat /etc/os-release | grep "VERSION_ID" | cut -d"\"" -f2)
       if [[ $distrib == "debian" ]]; then
         echo "deb http://download.opensuse.org/repositories/security:/zeek/Debian_$version/ /" > /etc/apt/sources.list.d/security:zeek.list
         wget -nv "https://download.opensuse.org/repositories/security:zeek/Debian_$version/Release.key" -O Release.key
       elif [[ $distrib == "ubuntu" ]]; then
         echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_$version/ /" > /etc/apt/sources.list.d/security:zeek.list
         wget -nv "https://download.opensuse.org/repositories/security:zeek/xUbuntu_$version/Release.key" -O Release.key
       elif [[ $distrib == "raspbian" ]]; then
         echo "deb http://download.opensuse.org/repositories/security:/zeek/Raspbian_$version/ /" > /etc/apt/sources.list.d/security:zeek.list
         wget -nv "https://download.opensuse.org/repositories/security:zeek/Raspbian_$version/Release.key" -O Release.key
       fi
       apt-key add - < Release.key
       rm Release.key && sudo apt-get update
       apt-get install zeek -y
    elif [[ $1 == "node" ]]; then
       curl -sL https://deb.nodesource.com/setup_14.x | bash -
       apt-get install -y nodejs
    elif [[ $1 == "dig" ]]; then
       apt-get install -y dnsutils
    elif [[ $1 == "pip" ]]; then
       apt-get install -y python3-pip
    elif [[ $1 == "dhcpcd" ]]; then
       apt-get install -y dhcpcd5
   fi
}

check_dnsmasq() {
   readlink /etc/resolv.conf
   status=$?
   if [[ $status -eq 0 && -f "/usr/sbin/dnsmasq" ]]; then
      systemctl disable systemd-resolved
      systemctl stop systemd-resolved
      unlink /etc/resolv.conf
      echo "nameserver 8.8.8.8" | tee /etc/resolv.conf
      install_package dnsmasq
   else
      install_package dnsmasq
   fi
}

check_dependencies() {
   # Check binary dependencies associated to the project.
   # If not installed, call install_package with the package name.
   check_dnsmasq
   bins=("/usr/sbin/hostapd"
         "/opt/zeek/bin/zeek"
         "/usr/bin/tshark"
         "/usr/bin/dig"
         "/usr/bin/suricata"
         "/usr/bin/unclutter"
         "/usr/bin/sqlite3"
         "/usr/bin/pip"
      	 "/usr/bin/swig"
	       "/usr/sbin/dhcpcd"
	       "/usr/bin/curl")

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
   install_package node
   echo -e "\e[39m[+] Install Python packages...\e[39m"
   python3 -m pip install -r "$SCRIPT_PATH/assets/requirements.txt"
}

compile_vuejs() {
    # Installing packages, updating packages and compiling the VueJS interfaces
    echo -e "\e[39m[+] Compiling VueJS projects"
    cd /usr/share/tinycheck/app/backend/ && npm install && npm audit fix && npm run build
    cd /usr/share/tinycheck/app/frontend/ && npm install && npm audit fix && npm run build
}

create_desktop() {
    # Create desktop icon to lauch TinyCheck in a browser
    if [[ -d "/home/$CURRENT_USER/Desktop/" ]]; then
    echo -e "\e[39m[+] Create Desktop icon under /home/${CURRENT_USER}/Desktop\e[39m"
    cat >"/home/$CURRENT_USER/Desktop/tinycheck.desktop" <<EOL
#!/usr/bin/env xdg-open

[Desktop Entry]
Version=1.0
Type=Application
Terminal=false
Exec=bash /usr/share/tinycheck/kiosk.sh
Name=TinyCheck
Comment=Launcher for the TinyCheck frontend
Icon=/usr/share/tinycheck/app/frontend/src/assets/icon.png
EOL
     fi
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
    sudo apt autoremove -y &> /dev/null
}

check_interfaces(){

    # Get the current connected interface name.
    ciface="$(ip r l default |grep -Po '(?<=(dev ))(\S+)')"

    # Setup of iface_out which can be any interface,
    # but needs to be connected now or in the future.
    echo -n "[?] The interface $ciface is connected. Do you want to use it as a bridge to Internet (network/out) ? [Yes/No] "
    read answer
    if [[ "$answer" =~ ^([yY][eE][sS]|[yY])$ ]]
    then
        IFACES=( "${IFACES[@]/$ciface}" )
        IFACE_OUT=$ciface
        echo -e "\e[92m    [✔] $ciface settled as a bridge to the Internet\e[39m"
    else
        IFACES=( "${IFACES[@]/$ciface}" )
        for iface in $IFACES;
        do
            config="$(ip a s $iface)"
            echo -n "[?] Do you want to use $iface as a bridge to Internet (network/out) ? [Y/n] "
            read answer
            if [[ "$answer" =~ ^([yY][eE][sS]|[yY])$ ]]
            then
                IFACE_OUT=$iface
                IFACES=( "${IFACES[@]/$iface}" )
                echo -e "\e[92m    [✔] $iface settled as a bridge to the Internet\e[39m"
                break
            fi
        done
    fi

    # Setup of iface_in which can be a only a
    # Wi-Fi interface with AP mode available.
    for iface in $IFACES;
    do
        if echo "$iface" | grep -Eq "(wlan[0-9]|wl[a-z0-9]{,20})"; then
            config="$(ip a s $iface)"                             # Get the iface logic configuration

            if echo "$config" | grep -qv "inet "; then              # Test if not currently connected
                hw="$(iw $iface info | grep wiphy | cut -d" " -f2)" # Get the iface hardware id.
                info="$(iw phy$hw info)"                            # Get the iface hardware infos.
                if echo "$info" | grep -qE "* AP$"; then            # Know if the iface has the AP mode available.
                    echo -n "[?] The interface $iface can be used for the Wi-Fi Access Point. Do you want to use it for the TinyCheck Access Point ? [Yes/No] "
                    read answer
                    if [[ "$answer" =~ ^([yY][eE][sS]|[yY])$ ]]
                    then
                        IFACE_IN="$iface"
                        echo -e "\e[92m    [✔] $iface settled as an Access Point\e[39m"
                        break
                    fi
                fi
            fi
        fi
    done
    if [ "${IFACE_IN}" != "" ] && [ "${IFACE_OUT}" != "" ]; then
        echo -e "\e[92m    [✔] Network configuration settled!\e[39m"
    else
        echo -e "\e[91m    [✘] You must select two interfaces, exiting.\e[39m"
        exit 1
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
    echo -e "\e[39m[+] Feeding your TinyCheck instance with fresh IOCs and whitelist, please wait."
    python3 /usr/share/tinycheck/server/backend/watchers.py 2>/dev/null
}

reboot_box() {
    echo -e "\e[92m[+] The system is going to reboot, OK ?\e[39m"
    read answer
    if [[ "$answer" =~ ^([yY][eE][sS]|[yY])$ ]]
    then
	sleep 5
	reboot
    else
	exit
    fi
}

if [[ $EUID -ne 0 ]]; then
    echo "This must be run as root. Type in 'sudo bash $0' to run."
	exit 1
elif [[ -f /usr/share/tinycheck/config.yaml ]]; then
    echo "You have a TinyCheck instance already installed on this box."
    echo "  - If you want to update the instance, please execute:"
    echo "      sudo bash /usr/share/tinycheck/update.sh"
    echo "  - If you want to uninstall the instance, please execute:"
    echo "      sudo bash /usr/share/tinycheck/uninstall.sh"
	exit 1
else
    welcome_screen
    check_operating_system
    check_interfaces
    create_directory
    get_version
    set_userlang
    set_credentials
    set_kioskmode
    set_update
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
