from abc import ABC, abstractmethod

from base.status import CheckStatus


class Module(ABC):
    """
    Base class for all modules to be used in secureme.

    :ivar str _iface: Name of the interface to secure on
    :ivar CheckStatus _status: Current module status
    """

    def __init__(self, iface: str = None):
        self._iface: str = iface
        self._status: CheckStatus = CheckStatus.WARN

    @abstractmethod
    def activate(self) -> None:
        """Activate the module - must not block!"""
        pass

    @abstractmethod
    def deactivate(self) -> None:
        """Deactivate the module"""
        pass

    def get_status(self) -> CheckStatus:
        """Get the module's current status"""
        return self._status
