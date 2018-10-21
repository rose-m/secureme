from scapy.all import conf

from checks.arp import ARPCheck
from checks.proxy import ProxyCheck

# Disable verbose mode of Scapy
conf.verb = 0


def main():
    iface = "en0"

    arp_check = ARPCheck(iface=iface, ping_check_ip="8.8.8.8")
    proxy_check = ProxyCheck()

    arp_check.activate()
    proxy_check.activate()

    input("Press ENTER to stop program...\n")

    arp_check.deactivate()
    proxy_check.deactivate()


if __name__ == '__main__':
    main()
