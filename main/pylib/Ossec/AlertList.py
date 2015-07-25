#!/usr/bin/env python

"""
/**
 * Ossec Framework
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @category   Ossec
 * @package    Ossec
 * @version    $Id: Histogram.php,v 1.3 2008/03/03 15:12:18 dcid Exp $
 * @author     Chris Abernethy
 * @copyright  Copyright (c) 2007-2008, Daniel B. Cid <dcid@ossec.net>, All rights reserved.
 * @license    http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 */
"""

##############################################################
#  Copyright C) 2015 Masashi Okumura All rights reseerved.
##############################################################


#from collections import OrderedDict

from datetime import *

from .Histogram import Ossec_Histogram

class Ossec_AlertList(object):
    def __init__(self):
        #self._alerts = OrderedDict()
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


    def earliest(self):
        return self._alerts[0]


    def latest(self):
        return self._latest

    def size(self):
        return len(self._alerts)


    def toHtml(self):
        buffer = ""

        first = self.earliest()
        first = datetime.fromtimestamp(int(first.time)).strftime("%m/%d/%Y %H:%M:%S")

        last = self.latest()
        last = datetime.fromtimestamp(int(last.time)).strftime("%m/%d/%Y %H:%M:%S")

        buffer += """<div id="alert_list_nav">"""

        buffer += self._tallyNav(self._level_histogram, 'level', 'severity', '+Severity breakdown')
        buffer += self._tallyNav(self._id_histogram, 'id', 'rule', '+Rules breakdown')

        buffer += "</div>"
        buffer += "<br/>"

        buffer += """
<table width="100%%">
<tr><td><b>First event</b> at <a href="#lt">%s</a></td></tr>
<tr><td><b>Last event</b> at <a href="#ft">%s</a></td></tr>
</table>
<br />""" % (first, last)

        buffer += """\
        <h2>Alert list</h2>
        <div id="alert_list_content">
            <a name="ft" ></a>
        """

        for alert in reversed(self._alerts):
            buffer += alert.toHtml()

        buffer += """\
                    <a name="lt" ></a>
        </div>
        """


        return buffer


    def _tallyNav(self, histogram, key, description, title):
        buffer = ""

        return buffer
        pass
