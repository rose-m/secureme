from scapy.all import conf

from checks.arp import ARPCheck
from checks.deauth import DeauthCheck

conf.verb = 0


def main():
    iface = "en0"
    # arp_check = ARPCheck(iface=iface, ping_check_ip="192.168.1.1")
    # arp_check.activate()

    deauth_check = DeauthCheck(iface=iface)
    deauth_check.activate()

    input("Press ENTER to stop program...\n")

    # arp_check.deactivate()
    deauth_check.deactivate()


if __name__ == '__main__':
    main()
