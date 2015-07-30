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
# ClassCat(R) Prism for HIDS
#  Copyright (C) 2015 ClassCat Co.,Ltd. All rights reseerved.
##############################################################

# ===  Notice ===
# all python scripts were written by masao (@classcat.com)
#
# === TODO ===
# 29-jul-15 :  src ip 毎の集計
#
# === History ===
# 30-jul-15 : fixed for beta.
#

from datetime import *

from collections import OrderedDict

from .Histogram import Ossec_Histogram

class Ossec_AlertList(object):
    def __init__(self, conf):
        self.conf = conf

        #self._alerts = OrderedDict()
        self._alerts = [] # TODO : ただのリストで良い？

        self._earliest = None # alert object
        self._latest = None

        self._id_histogram = Ossec_Histogram()  # Rule ID 毎の集計
        self._level_histogram = Ossec_Histogram()  # Level 毎の集計
        self._srcip_histogram = Ossec_Histogram()  # Src IP 毎の集計


    # Return the array of alerts
    def alerts(self):
        return self._alerts


    def addAlert(self, alert):
        self._id_histogram.count(str(alert.id))  # default は 1 をインクリメント
        self._srcip_histogram.count(str(alert.srcip))  # TODO : srcip がない場合はどうする？ それから、src ip 毎の集計は？
        self._level_histogram.count(str(alert.level))

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
        is_lang_ja = False
        if self.conf.lang == 'ja':
            is_lang_ja = True

        buffer = ""

        first = self.earliest()
        first = datetime.fromtimestamp(int(first.time)).strftime("%m/%d/%Y %H:%M:%S")

        last = self.latest()
        last = datetime.fromtimestamp(int(last.time)).strftime("%m/%d/%Y %H:%M:%S")

        buffer += """<div id="alert_list_nav">"""

        if is_lang_ja:
            buffer += self._tallyNav(self._level_histogram, 'level', 'severity', '+重要度・ブレークダウン')
            buffer += self._tallyNav(self._id_histogram, 'id', 'rule', '+ルール・ブレークダウン')
            buffer += self._tallyNav(self._srcip_histogram, 'srcip', 'Source IP', '+ソース IP・ブレークダウン' )
        else:
            buffer += self._tallyNav(self._level_histogram, 'level', 'severity', '+Severity breakdown')
            buffer += self._tallyNav(self._id_histogram, 'id', 'rule', '+Rules breakdown')
            buffer += self._tallyNav(self._srcip_histogram, 'srcip', 'Source IP', '+Src IP breakdown' )

        buffer += "</div>"
        buffer += "<br/>"

        if is_lang_ja:
            buffer += """
<table width="100%%">
<tr><td><b>最初のイベント</b> : <a href="#lt">%s</a></td></tr>
<tr><td><b>最後のイベント</b> : <a href="#ft">%s</a></td></tr>
</table>
<br />""" % (first, last)
        else:
            buffer += """
<table width="100%%">
<tr><td><b>First event</b> at <a href="#lt">%s</a></td></tr>
<tr><td><b>Last event</b> at <a href="#ft">%s</a></td></tr>
</table>
<br />""" % (first, last)

        if is_lang_ja:
            buffer += """\
        <h2>Alert リスト</h2>
        <div id="alert_list_content">
            <a name="ft" ></a>
        """
        else:
            buffer += """\
        <h2>Alert list</h2>
        <div id="alert_list_content">
            <a name="ft" ></a>
        """

        lang = "en"
        if is_lang_ja:
            lang = "ja"
        for alert in reversed(self._alerts):
            buffer += alert.toHtml(lang)

        buffer += """\
            <a name="lt" ></a>
        </div>
        """

        buffer += """\

<script type="text/javascript">

            // Get a list of all key/id combos. This is used in the Show
            // Only and Clear Restrictions functionality.

            var cnames = [];
            $$('#alert_list_content div.alert').each(function(el){
              cnames = cnames.concat($w(el.className).grep(/^(id|level|srcip)/)).uniq();
            });

            // Open or close the navigation link set for the key clicked.

            $$('#alert_list_nav div.toggle').each(function(el){
                Event.observe( el, 'click', function(e) { Event.stop(e);
                    el.childElements().grep(new Selector("div.details")).invoke('toggle');
                });
            });

            // Clear the current restrictions for a key. Show all alerts for
            // that key type, and update the nav for all ids in that key.

            $$('#alert_list_nav a.clear').each(function(el){
                var mycname = $w(el.className).grep(/^(id|level|srcip)/);
                var re_type = new RegExp('^' + (''+mycname).split('_')[0]);
                Event.observe( el, 'click', function(e){ Event.stop(e);
                    cnames.grep(re_type).each(function(c){
                        $$('#alert_list_content .' + c ).invoke('show');
                        $('showing_' + c).show(); $('hiding_' + c).hide();
                    });
                })
            });

            // Hide all alerts having the key/id clicked and update the
            // nav links for that id.

            $$('#alert_list_nav a.hide').each(function(el){
                var mycname = $w(el.className).grep(/^(id|level|srcip)/);
                Event.observe( el, 'click', function(e){ Event.stop(e);
                    $$('#alert_list_content .' + mycname ).invoke('hide');
                    $('showing_' + mycname, 'hiding_' + mycname).invoke('toggle');
                })
            });

            // Hide all alerts not having the key/id clicked and update
            // the nav links for the rest of the ids in the key clicked.

            $$('#alert_list_nav a.only').each(function(el){
                var mycname = $w(el.className).grep(/^(id|level|srcip)/);
                var re_type = new RegExp('^' + (''+mycname).split('_')[0]);
                Event.observe( el, 'click', function(e){ Event.stop(e);
                    $$('#alert_list_content div.alert').each(function(el){
                        el.hasClassName(mycname) ? null : el.hide();
                    });
                    cnames.without(mycname).grep(re_type).each(function(c){
                        $('showing_' + c).hide(); $('hiding_' + c).show();
                    });
                });
            });

            // Show all alerts for the key/id clicked and update the nav
            // links for that id.

            $$('#alert_list_nav a.show').each(function(el){
                var mycname = $w(el.className).grep(/^(id|level|srcip)/);
                Event.observe( el, 'click', function(e){ Event.stop(e);
                    $$('#alert_list_content .' + mycname ).invoke('show');
                    $('showing_' + mycname, 'hiding_' + mycname).invoke('toggle');
                })
            });

</script>
        """

        return buffer


    def _tallyNav(self, histogram, key, description, title):
        tally = histogram.getRaw()
        arsorted_tally_list = sorted(tally.items(), key=lambda x: x[1], reverse=True)

        buffer = ""

        buffer += """
<div class="alert_list_nav">
    <div class="asmall toggle">
        <a href="#" title="%s" class="black bigg" style="font-weight:bold;"><span style="color:#333">%s</span></a>
        <div class="asmall details" style="display:none">
        """ % (title, title)

        for _id, count in arsorted_tally_list:

            buffer += """
                <div id="showing_%s_%s" class="asmall">
                        Showing %s alert(s) from <b>%s %s</b>
                        <a href="#" class="asmall hide %s_%s" title="Hide this %s">(hide)</a>
                        <a href="#" class="asmall only %s_%s" title="Show only this %s">(show only)</a>
                </div>
            """ % (key, _id, count, key, _id, key, _id, key, key, _id, key)

            buffer += """
                <div id="hiding_%s_%s" class="asmall" style="display:none;">
                        Hiding %s alert(s) from <b>%s %s</b>
                        <a href="#" class="asmall show %s_%s" title="Hiding %s">(show)</a>
                </div>
            """ % (key, _id, count, key, _id, key, _id, key)

        buffer += """<a href="#" class="asmall clear %s" title="Clear %s restrictions">Clear %s restrictions</a> """ % (key, description, key)

        buffer += """
        </div>
    </div>
</div>
        """

        return buffer


### End of Script ###
