from threading import Timer
from urllib import request

from bs4 import BeautifulSoup

from base.module import Module


class ProxyCheck(Module):
    _periodic_timer: Timer

    PROXY_CHECK_INTERVAL = 15

    def __init__(self):
        super(ProxyCheck, self).__init__()

        self._periodic_timer = None

    def activate(self):
        self._initialize_fingerprints()
        self._do_periodic_check()
        self._setup_timer()

    def deactivate(self):
        pass

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
        print("check")

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
                fingerprints.append((name, sha))

            print(fingerprints)
