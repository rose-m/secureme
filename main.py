from scapy.all import conf

from checks.proxy import ProxyCheck

conf.verb = 0


def main():
    iface = "en0"
    # arp_check = ARPCheck(iface=iface, ping_check_ip="192.168.1.1")
    # arp_check.activate()

    proxy_check = ProxyCheck()
    proxy_check.activate()

    input("Press ENTER to stop program...\n")

    # arp_check.deactivate()
    proxy_check.deactivate()


if __name__ == '__main__':
    main()
