from enum import Enum, unique


@unique
class CheckStatus(Enum):
    """
    Used to identify the status of a security check
    """

    OK = 'OK'
    """No anomalies detected; everything secure"""

    WARN = 'WARN'
    """Anomalies have been detected; not clearly a threat, needs suspicion"""

    ALERT = 'ALERT'
    """Threat has been detected"""

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
