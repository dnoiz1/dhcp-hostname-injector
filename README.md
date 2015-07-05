# DHCP hostname injector

Used for setting your DHCP hostname to things that could break your router.
Generally this will get XSS on poorly coded SOHO router web interfaces.    

I'm sure theres probably a billion other things that do this - I don't care.    

Inspired by <a target="_blank" href="https://twitter.com/silviocesare">@silviocesare</a> cos I think he did it once.

### Author
Tim Noise <tim@drkns.net>

### Installation
git clone https://github.com/dnoiz1/dhcp-hostname-injector.git

### Usage
Best used on a secondary interface. ~captain obvious~

- Make sure your interface is not configured already, comment it out in ```/etc/network/interfaces``` and ```sudo service networking restart```
- Edit the payload variable in ```dhcp.py``` to whatever

> Wired
```console
sudo ifconfig eth1 up
sudo ./dhcp.py eth1
```

> Wireless
Before you use this on wireless, make sure rfkill hasnt disabled your radio, etc
```console
sudo ifconfig wlan0 up
wpa_passphrase My Target Network Name > ./wpa_supplicant.conf
sudo ./wpa_dhcp.sh wlan0
```

### Dependancies
```console
sudo apt-get install wireless-tools scapy
```

### Notes
- Only really tested on ubuntu 14.04 - may or may not be DHCP compliant.
- I haven't done a wide range of testing, nor do I plan to.
- You may need to man wpa_supplicant and RTFM to get wpa_supplicant to work on its own first.
- theres a min length for the hostname field of 1 in RFC 2132 section 3.14
- "allowed characters" are in RFC 1035 - use the term allowed lightly.
- Its just using scapy, so modify as necessary to inject other params
