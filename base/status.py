from enum import Enum, unique


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
