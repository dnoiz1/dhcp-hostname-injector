#!/bin/sh
if [ `whoami` != "root" ]; then
    echo "[!] run as root to assoc"
    exit 1
fi

if [ -z "$@" ]; then
    echo "[!] missing interface"
    echo "[+] usage: $0 <interface>"
    exit 1
fi

if [ ! -f "./wpa_supplicant.conf" ]; then
    echo "[!] create ./wpa_supplicant.conf with wpa_passphrase <ssid> > ./wpa_supplicant.conf"
    exit 1
fi

echo "[+] starting on interface $@\n[+] killing any active wpa_supplicant instances"

killall wpa_supplicant 2>&1 > /dev/null
sleep 1
echo "[+] starting wpa_supplicant"
wpa_supplicant -i$@ -c ./wpa_supplicant.conf -Dwext -B
sleep 5
echo "[+] should be assoc now... "

IW=$(iwconfig $@)

ASSOC=$(echo $IW | grep 'Not' | wc -l)

if [ $ASSOC -eq 1 ]; then
    echo "[!] Not associated, check ./wpa_supplicant.conf"
fi

echo $(echo $IW | awk '{ print "[+] sucessfully associated to " $4 " BSSID:"$10 }')

python ./dhcp.py $@
