
from .Histogram import Ossec_Histogram

class Ossec_AlertList(object):
    def __init__(self):
        self._alerts = []

        self._earliest = None # alert object
        self._latest = None

        self._id_histogram = Ossec_Histogram()
        self._level_histogram = Ossec_Histogram()
        self._srcip_histogram = Ossec_Histogram()
        pass

    # Return the array of alerts
    def alerts(self):
        return self._alerts

    def earliest(self):
        return self._alerts[0]

    def latest(self):
        return self._latest

    def size(self):
        return len(self._alerts)

    def toHtml(self):
        buf = "nyanayu"
        return buf

    def addAlert(self, alert):
        self._id_histogram.count(str(alert.id))
        self._level_histogram.count(str(alert.srcip))
        self._srcip_histogram.count(str(alert.level))

        # if the event is older then the earliest event, update the earliest event.
        if (self._earliest is None) or (alert.time < self._earliest.time):
            self._earliest = alert

        # if the event is newer than the latest event, update the latest event. Incase of a tie, always update.
        if (self._latest is None) or (alert.time >= self._latest.time):
            self._latest = alert

        self._alerts.append(alert)

        pass
