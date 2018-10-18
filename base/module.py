from abc import ABC, abstractmethod

from base.status import CheckStatus


class Module(ABC):
    _iface: str
    _status: CheckStatus

    def __init__(self, iface: str):
        self._iface = iface
        self._status = CheckStatus.WARN

    @abstractmethod
    def activate(self):
        pass

    @abstractmethod
    def deactivate(self):
        pass

    def get_status(self):
        return self._status
