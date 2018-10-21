from collections import namedtuple
from socket import socket
from threading import Timer
from typing import List, Optional
from urllib import request

from OpenSSL import SSL
from OpenSSL.crypto import X509
from bs4 import BeautifulSoup

from base.module import Module
from base.status import CheckStatus

Fingerprint = namedtuple(typename="Fingerprint",
                         field_names=["name", "sha1"])


def get_ssl_cert() -> Optional[List[X509]]:
    with socket() as sock:
        sock.connect(("www.google.com", 443))
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        conn = SSL.Connection(ctx, sock)
        conn.set_connect_state()
        conn.do_handshake()

        cert_chain = conn.get_peer_cert_chain()
        conn.close()
        return cert_chain


class ProxyCheck(Module):
    """
    Checks if there is a malicious proxy intercepting HTTPS traffic.

    The module first tries to extract all now Google CA Fingerprints by parsing https://pki.goog. Once
    the fingerprints have been loaded it periodically does a HTTPS request to https://www.google.com:443
    and checks the certificate chain whether a fingerprint matches the known CAs.

    :ivar Timer _periodic_timer: Timer for periodic check
    :ivar List[Fingerprint] _fingerprints: List of known fingerprints
    """

    PROXY_CHECK_INTERVAL = 15
    """Periodic check interval in seconds"""

    def __init__(self):
        super(ProxyCheck, self).__init__()

        self._periodic_timer: Timer = None
        self._fingerprints: List[Fingerprint] = []

    def activate(self):
        self._do_periodic_check()

    def deactivate(self):
        self._reset_timer()

    def _setup_timer(self):
        self._reset_timer()
        self._periodic_timer = Timer(ProxyCheck.PROXY_CHECK_INTERVAL, self._do_periodic_check)
        self._periodic_timer.daemon = True
        self._periodic_timer.start()

    def _reset_timer(self):
        if self._periodic_timer is not None:
            self._periodic_timer.cancel()
            self._periodic_timer = None

    def _do_periodic_check(self):
        if len(self._fingerprints) == 0:
            self._status = CheckStatus.WARN
            self._initialize_fingerprints()
        else:
            self._check_certificate()

        print(">> ProxyCheck: %s" % self._status)
        self._setup_timer()

    def _check_certificate(self):
        certs: Optional[List[X509]] = None
        try:
            certs = get_ssl_cert()
        except Exception as e:
            print("Error: %s" % e)

        if certs is None or len(certs) == 0:
            self._status = CheckStatus.ALERT
            return

        site_cert = certs[0]
        site_subject = site_cert.get_subject()
        cns = [v for n, v in site_subject.get_components() if n == b'CN']
        if len(cns) > 0 and cns[0] != b'www.google.com':
            self._status = CheckStatus.ALERT
            return

        cert_shas = [(cert, str(cert.digest("sha1"))[2:-1].lower()) for cert in certs]
        for cert, sha in cert_shas:
            for fp in self._fingerprints:
                if fp.sha1 == sha:
                    print("Matching: %s - %s" % (fp.name, fp.sha1))
                    self._status = CheckStatus.OK
                    return

        self._status = CheckStatus.ALERT

    def _initialize_fingerprints(self):
        def beauty(content):
            return BeautifulSoup(content, features="html.parser")

        with request.urlopen('https://pki.goog') as req:
            soup = beauty(req.read())
            rows = soup.select('#maia-main table tbody tr')

            fingerprints = []
            for r in rows:
                tds = r.select("td")
                name = tds[0].getText().strip()
                sha = tds[2].getText().strip()
                fingerprints.append(Fingerprint(name=name, sha1=sha))

            self._fingerprints = fingerprints
