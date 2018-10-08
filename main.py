from enum import Enum, auto, unique

from scapy.all import sniff, sr, sr1, conf
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, ICMP
from threading import Timer, Thread, RLock, _RLock

conf.verb = 0


@unique
class CheckStatus(Enum):
    OK = 'OK'
    WARN = 'WARN'
    ALERT = 'ALERT'

    def increase(self):
        if self == CheckStatus.OK:
            return CheckStatus.WARN
        else:
            return CheckStatus.ALERT

    def decrease(self):
        if self == CheckStatus.ALERT:
            return CheckStatus.WARN
        else:
            return CheckStatus.OK


class ARPCheck(object):
    _iface: str
    _check_status: CheckStatus

    _gateway_ip: str
    _expected_gateway_mac: str
    _correct_gateway_counter: int

    _periodic_timer: Timer
    _sniff_thread: Thread
    _interrupted: bool
    _thread_lock: _RLock

    GATEWAY_CHECK_INTERVAL: int = 10
    UNIQUE_GATEWAYS_FOR_COOLDOWN: int = 3  # 3 times period check unique -> 30s continuous

    def __init__(self, iface: str):
        self._iface = iface
        self._check_status = CheckStatus.WARN

        self._gateway_ip = None
        self._expected_gateway_mac = None
        self._correct_gateway_counter = 0

        self._periodic_timer = None
        self._sniff_thread = None
        self._interrupted = False
        self._thread_lock = RLock()

    def activate(self):
        self._do_periodic_check()

        if self._sniff_thread is None:
            self._interrupted = False
            self._sniff_thread = Thread(target=self._start_sniffing,
                                        name="arp-passive-check",
                                        daemon=True)
            self._sniff_thread.start()

    def deactivate(self):
        if self._sniff_thread is not None:
            self._interrupted = True
            self._sniff_thread.join(ARPCheck.GATEWAY_CHECK_INTERVAL + 5)
            if not self._sniff_thread.is_alive():
                self._sniff_thread = None

        self._reset_timer()

    def _start_sniffing(self):
        try:
            sniff(iface=self._iface, filter="arp", store=False,
                  prn=self._handle_packet)
        except InterruptedError:
            pass

    def _handle_packet(self, pkt):
        if self._interrupted:
            raise InterruptedError

        if self._gateway_ip is None or ARP not in pkt:
            return

        pkt_arp: ARP = pkt[ARP]
        if (pkt_arp.op == 2
                and pkt_arp.psrc == self._gateway_ip
                and pkt_arp.hwsrc != self._expected_gateway_mac):
            print("ARP with diverging information: %s " % pkt_arp.summary())
            self._reset_to_alert()

    def _setup_timer(self):
        self._reset_timer()
        self._periodic_timer = Timer(ARPCheck.GATEWAY_CHECK_INTERVAL, self._do_periodic_check)
        self._periodic_timer.daemon = True
        self._periodic_timer.start()

    def _reset_timer(self):
        if self._periodic_timer is not None:
            self._periodic_timer.cancel()
            self._periodic_timer = None

    def _do_periodic_check(self):
        self._check_gateway()
        self._setup_timer()

    def _check_gateway(self):
        print("Checking current gateway...")
        # TODO: add timeout...
        response = sr1(IP(dst="8.8.8.8", ttl=0) / ICMP())
        response_ip = response[IP]
        print("Found gateway IP: %s" % response_ip.src)
        used_gateway = response_ip.src

        ans, _ = sr(ARP(pdst=used_gateway))
        arp_replies = ans.filter(
            lambda s_r: ARP in s_r[1] and s_r[1][ARP].op == 2)

        received_macs = set()
        for _, rcv in arp_replies:
            print("ARP packet: %s" % rcv.summary())
            if rcv[ARP].psrc != used_gateway:
                continue

            received_macs.add(rcv[ARP].hwsrc)

        if len(received_macs) > 1:
            print("----> ARP request for %s returned multiple macs: %s" %
                  (used_gateway, received_macs))
            self._reset_to_alert()
        elif len(received_macs) == 1:
            with self._thread_lock:
                self._gateway_ip = used_gateway
                self._expected_gateway_mac = received_macs.pop()
                if self._correct_gateway_counter < ARPCheck.UNIQUE_GATEWAYS_FOR_COOLDOWN * 2:
                    self._correct_gateway_counter += 1

                    if (self._correct_gateway_counter >= ARPCheck.UNIQUE_GATEWAYS_FOR_COOLDOWN
                            and self._check_status != CheckStatus.OK):
                        self._check_status = CheckStatus.OK if self._check_status == CheckStatus.WARN \
                            else CheckStatus.WARN
                else:
                    self._check_status = CheckStatus.OK

            print("ARP behavior normal - current status: %s" % self._check_status)

    def _reset_to_alert(self):
        with self._thread_lock:
            self._gateway_ip = None
            self._expected_gateway_mac = None
            self._correct_gateway_counter = 0
            self._check_status = CheckStatus.ALERT

        print("ALERT - POTENTIAL ARP SPOOF UNDER WAY!")
        print("----> current status: %s" % self._check_status)


def main():
    iface = "en0"
    arp_check = ARPCheck(iface)
    arp_check.activate()

    input("Press ENTER to stop program...\n")

    arp_check.deactivate()


if __name__ == '__main__':
    main()
