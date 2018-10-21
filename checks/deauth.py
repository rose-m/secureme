from scapy.all import sniff, Thread, Scapy_Exception

from base.module import Module
from base.status import CheckStatus


class DeauthCheck(Module):
    """
    Checks if there are unexpected deauth packets being sent over WiFi.

    **WARNING**: This module does only work when the interface is in monitor mode. Therefore
    implementation is incomplete...
    """

    _sniff_thread: Thread
    _interrupted: bool

    def __init__(self, iface: str):
        super(DeauthCheck, self).__init__(iface)

        self._sniff_thread = None
        self._interrupted = False

    def activate(self):
        if self._sniff_thread is None:
            self._interrupted = False
            self._sniff_thread = Thread(target=self._start_sniffing,
                                        name="deauth-check",
                                        daemon=True)
            self._sniff_thread.start()

    def deactivate(self):
        if self._sniff_thread is not None:
            self._interrupted = True
            self._sniff_thread.join(5)
            if not self._sniff_thread.is_alive():
                self._sniff_thread = None

    def _start_sniffing(self):
        try:
            sniff(iface=self._iface,
                  filter="wlan type mgt",
                  store=False,
                  prn=self._handle_packet)
        except Scapy_Exception as e:
            msg: str = e.args[0]
            if msg.startswith('Got an empty BPF'):
                print(">> DeauthCheck: cannot be enabled - WiFi must be in monitor mode")
                self._status = CheckStatus.WARN
        except InterruptedError:
            pass

    def _handle_packet(self, pkt):
        if self._interrupted:
            raise InterruptedError

        print(pkt.summary())
