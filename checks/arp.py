from threading import Timer, Thread, RLock

from scapy.all import sniff, sr1, sr
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import ARP

from base.module import Module
from base.status import CheckStatus


class ARPCheck(Module):
    """
    Checks for ARP spoofing attacks against the client.

    The module first tries to periodically check the gateway by doing an ICMP ping packet to `8.8.8.8`
    with `ttl=0` to get the reacting gateway. It then does an ARP Request for that IP and validates
    what ARP Replies come in - if there is a unique response and it matches the first one we found.

    Apart from that it listens on the given interface for ARP Replies and validates them against
    the known MAC for the gateway IP.

    :ivar str _ping_check_ip: IP to use for gateway IP extraction (default `8.8.8.8`)
    :ivar str _gateway_ip: IP of the suspected gateway
    :ivar str _expected_gateway_mac: MAC address of the suspected gateway
    :ivar int _correct_gateway_counter: Number of times the correct gateway has been seen
    :ivar Timer _periodic_timer: Timer for periodic checks
    :ivar Thread _sniff_thread: Thread containing the sniff for unexpected ARP Replies
    :ivar bool _interrupted: Flag to signal shutdown
    :ivar RLock _thread_lock: Lock to synchronize member updates
    """

    GATEWAY_CHECK_INTERVAL: int = 10
    """Periodic check interval in seconds"""

    UNIQUE_GATEWAYS_FOR_COOLDOWN: int = 3
    """Number of times to see correct gateway in order to lower check status"""

    def __init__(self, iface: str, ping_check_ip: str = "8.8.8.8"):
        super(ARPCheck, self).__init__(iface=iface)

        self._ping_check_ip = ping_check_ip

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
        response = sr1(IP(dst=self._ping_check_ip, ttl=0) / ICMP(), timeout=10)
        if not response:
            print("... no response")
            with self._thread_lock:
                if self._correct_gateway_counter > 0:
                    self._correct_gateway_counter -= 1
                if self._correct_gateway_counter == 0 and self._status != CheckStatus.ALERT:
                    self._status = CheckStatus.WARN
            return

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
                            and self._status != CheckStatus.OK):
                        self._status = CheckStatus.OK if self._status == CheckStatus.WARN \
                            else CheckStatus.WARN
                else:
                    self._status = CheckStatus.OK

            print("ARP behavior normal - current status: %s" % self._status)

    def _reset_to_alert(self):
        with self._thread_lock:
            self._gateway_ip = None
            self._expected_gateway_mac = None
            self._correct_gateway_counter = 0
            self._status = CheckStatus.ALERT

        print("ALERT - POTENTIAL ARP SPOOF UNDER WAY!")
        print("----> current status: %s" % self._status)
