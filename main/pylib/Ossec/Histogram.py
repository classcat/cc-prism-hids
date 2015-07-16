
class Ossec_Histogram(object):
    def __init__(self):
        # Histogram data stored as a hash.
        self._histogram = {}

    def count(self, key, num=1):
        # Increment the counter for the specified key by the given number (one, bydefault)
        if key not in self._histogram:
            self._histogram[key] = 0

        self._histogram[key] += int(num)
        pass

    def getRaw(self):
        return self._histogram


        pass
    pass
