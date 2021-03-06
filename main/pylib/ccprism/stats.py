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

import os,sys
import re

from flask import Flask, session, request, redirect, render_template, url_for
from flask import jsonify, make_response

from datetime import *
import time
import uuid
import hashlib

from collections import OrderedDict

from babel.numbers import format_decimal

import ossec_conf
import os_lib_handle
import os_lib_agent
import os_lib_alerts
import os_lib_stats
#import os_lib_syscheck

from ossec_categories import global_categories
from ossec_formats import log_categories

from .view import View

class Stats(View):

    def __init__(self, request):
        super().__init__()

        self.request = request

        self.html = ""
        self.contents=  ""

        self.is_post = False
        if request.method == 'POST':
            self.is_post = True

        self._make_contents()
        self._make_html()

    def _make_contents(self):
        req       = self.request
        is_post = self.is_post
        form     = req.form

        # Starting handle
        ossec_handle = os_lib_handle.os_handle_start(ossec_conf.ossec_dir)

        # Current date values (day : 05, month : 07, year : 2015)
        curr_time = int(time.time())
        curr_day =  datetime.fromtimestamp(curr_time).strftime("%d")
        curr_month = datetime.fromtimestamp(curr_time).strftime("%m")
        curr_year = datetime.fromtimestamp(curr_time).strftime("%Y")

        #  datetime.fromtimestamp(curr_time).strftime("%Y-%m-%d %H:%M")

        # Getting user values
        USER_day = None
        USER_month = None
        USER_year = None

        if is_post and ('day' in form):
            strday = form.get('day')
            if strday.isdigit():
                if (int(strday) >= 0) and (int(strday) <=31 ):
                    USER_day = strday
                    # USER_day = "%02d" % int(strday)  # TODO : キーをどうするか
                    print (USER_day)

        if is_post and ('month' in form):
            strmonth = form.get('month')
            if strmonth.isdigit():
                if (int(strmonth) > 0) and (int(strmonth) <=12):
                    USER_month = strmonth

        if is_post and ('year' in form):
            stryear = form.get('year')
            if stryear.isdigit():
                if (int(stryear) >= 1) and (int(stryear) <= 3000):
                    USER_year = stryear

        init_time = 0
        final_time = 0

        # Bulding stat time_stamp
        if (USER_year is not None) and (USER_month is not None) and (USER_day is not None):
            print ("UESR_day is %s" % USER_day)
            # Stat for whole month
            if int(USER_day) == 0:
                print ("OKOK")
                init_time = int(time.mktime((int(USER_year), int(USER_month), 1, 0, 0, 0, 0, 0, -1)))
                final_time = int(time.mktime((int(USER_year), int(USER_month) + 1, 0, 0, 0, 0, 0, 0, -1)))
                # 2015-12-01 00:00:00
                # 2015-12-31 00:00:00
                # print(datetime.fromtimestamp(init_time))
                # print(datetime.fromtimestamp(final_time))

            else:
                init_time = int(time.mktime((int(USER_year), int(USER_month), int(USER_day), 0, 0, 0, 0, 0, -1)))
                final_time = int(time.mktime((int(USER_year), int(USER_month), int(USER_day), 0, 0, 10, 0, 0, -1)))

        else:
            init_time = curr_time - 1
            final_time = curr_time

            # Setting user values
            USER_month = curr_month
            USER_day = curr_day
            USER_year = curr_year

        buffer = ""

        # Day option
        buffer += "<h2>Stats options</h2><br />\n"

        buffer += """\
        <form name="dosearch" method="post" action="stats">

Day:  <select name="day" class="formSelect">
    <option value="0">All days</option>
        """

        for l_counter in range(1, 32):
            tmp_msg = ""
            if l_counter == int(USER_day):
                tmp_msg = ' selected="selected"'
            buffer += """<option value="%s" %s>%s</option>""" % (l_counter, tmp_msg, l_counter)

        buffer += "</select>"

        # Monthly
        months = OrderedDict([
            ("January", "Jan"),
            ("February", "Feb"),
            ("March", "Mar"),
            ("April", "Apr"),
            ("May", "May"),
            ("June", "Jun"),
            ("July", "Jul"),
            ("August", "Aug"),
            ("September", "Sep"),
            ("October", "Oct"),
            ("November", "Nov"),
            ("December", "Dec")
        ])

        buffer += ' Month: <select name="month" class="formSelect">'

        mnt_ct = 1
        for tmp_month, tmp_month_v in months.items():
            if int(USER_month) == mnt_ct:
                buffer += """    <option value="%s" selected="selected">%s</option>""" % (mnt_ct, tmp_month)
            else:
                buffer += """    <option value="%s">%s</option>""" % (mnt_ct, tmp_month)

            mnt_ct += 1

        buffer += "</select>"

        # year
        buffer += """ Year: <select name="year" class="formSelect">
        <option value="%s" selected="selected">%s</option>
        <option value="%s">%s</option>
        <option value="%s">%s</option>
        </select> <input type="submit" name="Stats" value="Change options" class="button" /></form>""" % (curr_year, curr_year, int(curr_year) - 1, int(curr_year) -1, int(curr_year) -2, int(curr_year) -2)

        # Getting daily stats
        # 2015/Jul
        l_year_month = datetime.fromtimestamp(init_time).strftime("%Y/%b")

        print ("INIT_TIME")
        print (init_time)
        print(final_time)
        print (datetime.fromtimestamp(init_time).strftime("%Y/%m/%d %H:%M:%S"))
        print (datetime.fromtimestamp(final_time).strftime("%Y/%m/%d %H:%M:%S"))
        """
        1435676400
1438268400
2015/07/01 00:00:00
2015/07/31 00:00:00

        """


        stats_list = os_lib_stats.os_getstats(ossec_handle, init_time, final_time)

        print ("stats_list")
        print (stats_list)
        print ("USER_day %s"  % USER_day)

        daily_stats = OrderedDict()
        all_stats = None

        if l_year_month in stats_list.keys():
            for k in stats_list[l_year_month].keys():
                print ("key is : %s" %k)
            if str(USER_day) in stats_list[l_year_month].keys():
                print ("found ")
                daily_stats = stats_list[l_year_month][str(USER_day)]
                all_stats = stats_list[l_year_month]

        print (daily_stats)

        if not 'total' in daily_stats.keys():
            buffer += """<br/>
                <b class="red">No stats available.</b>
            """
            self.contents += buffer
            return

        else:
            buffer += "<br />"

        # Day 0 == month stats
        if USER_day == 0:
            buffer += "<h2>Ossec Stats for: <b id='blue'>%s</b></h2><br />\n" % l_year_month
        else:
            buffer += "<h2>Ossec Stats for: <b id='blue'>%s/%s</b> </h2><br /><br />\n\n" % (l_year_month, USER_day)



        buffer += "<b>Total</b>: " + format_decimal(daily_stats['total'], locale='en_US')+ "<br/>"
        buffer += "<b>Alerts</b>: " + format_decimal(daily_stats['alerts'], locale='en_US') + "<br/>"
        buffer += "<b>Syscheck</b>: " + format_decimal(daily_stats['syscheck'], locale='en_US') + "<br/>"
        buffer += "<b>Firewall</b>: " + format_decimal(daily_stats['firewall'], locale='en_US') + "<br/>"

        if USER_day != 0:
            h_avg = int(daily_stats['total']) / 24.0
            print (h_avg)
            buffer += "<b>Average</b>: " + "%.02f" % h_avg + " events per hour."

        buffer += """<br /><br />
<br /><div class="statssmall">
<table align="center"><tr valign="top"><td width="50%">

<table summary="Total values">
    <caption><strong>Aggregate values by severity</strong></caption>
    <tr>
    <th>Option</th>
    <th>Value</th>
    <th>Percentage</th>
    </tr>
        """

        """
        OrderedDict([('total', 24150), ('alerts', 18798), ('syscheck', 3), ('firewall', 0),
         ('level', OrderedDict([('5', 1), ('3', 17127), ('0', 1659), ('10', 1), ('7', 6), ('1', 3), ('2', 1)])),
         ('rule', OrderedDict([('5503', 1), ('5501', 4893), ('5521', 45), ('5502', 4892), ('5522', 45), ('5401', 1), ('5402', 7338), ('530', 1531), ('533', 6), ('535', 3), ('31100', 5), ('31108', 9), ('509', 22), ('12100', 2), ('591', 4), ('1002', 1)])), ('alerts_by_hour', OrderedDict([('0', '1344'), ('1', '1345'), ('2', '1341'), ('3', '1341'), ('4', '1361'), ('5', '1334'), ('6', '1345'), ('7', '1343'), ('8', '1340'), ('9', '1343'), ('10', '1341'), ('11', '1334'), ('12', '1342'), ('13', '1344')])), ('total_by_hour', OrderedDict([('0', '1724'), ('1', '1724'), ('2', '1722'), ('3', '1722'), ('4', '1741'), ('5', '1713'), ('6', '1728'), ('7', '1729'), ('8', '1739'), ('9', '1727'), ('10', '1721'), ('11', '1713'), ('12', '1723'), ('13', '1724')])), ('syscheck_by_hour', OrderedDict([('0', '0'), ('1', '0'), ('2', '0'), ('3', '0'), ('4', '0'), ('5', '0'), ('6', '0'), ('7', '0'), ('8', '0'), ('9', '3'), ('10', '0'), ('11', '0'), ('12', '0'), ('13', '0')])), ('firewall_by_hour', OrderedDict([('0', '0'), ('1', '0'), ('2', '0'), ('3', '0'), ('4', '0'), ('5', '0'), ('6', '0'), ('7', '0'), ('8', '0'), ('9', '0'), ('10', '0'), ('11', '0'), ('12', '0'), ('13', '0')]))])
[('5', 1), ('10', 1), ('2', 1), ('1', 3), ('7', 6), ('0', 1659), ('3', 17127)]

        """

        #sorted_daily_stats_level = None  # OrderedDict()

        odd_count = 0
        odd_msg = ""

        if 'level' in daily_stats.keys():
            #sorted_daily_stats_level = sorted(daily_stats['level'].items(), key=lambda x: x[1])
            #print (sorted_daily_stats_level)

            # 最初にキーでソートしておく。（同じ値の時に、キー順に並べるため）
            # TODO : 文字列ソートのため、10 -> 2 になっている。
            # 数字でソート
            level_dict = OrderedDict()
            for k, v in sorted(daily_stats['level'].items()):
                level_dict[k] = v

            for  l_level, v_level in sorted(level_dict.items(), key=lambda x: x[1]):
            # 10, 2, 5, 1, 7, 0, 3
            #for  l_level, v_level in sorted(daily_stats['level'].items(), key=lambda x: x[1]):
            # 5, 10, 2, 1, 7, 0, 3

                level_pct = (v_level*100)/daily_stats['alerts']
                if (odd_count %2) == 0:
                    odd_msg = ' class="odd"'
                else:
                    odd_msg = ""

                odd_count += 1

                buffer += """
                <tr %s>
                    <td>Total for level%s</td>
                    <td>%s</td>
                    <td>%s %%</td>
                """ % (odd_msg, l_level, format_decimal(v_level, locale='en_US'), "%.01f" % level_pct)

        #print ("result is :")
        #print(sorted_daily_stats_level)

        if (odd_count % 2) == 0:
            odd_msg =  ' class="odd"'
        else:
            odd_msg = ""

        buffer += """
        <tr %s>
<td>Total for all levels</td>
<td>%s</td>
<td>100%%</td>
</tr>
</table>

</td>

<td width="50%%">
<table summary="Total values">
    <caption><strong>Aggregate values by rule</strong></caption>
    <tr>
    <th>Option</th>
    <th>Value</th>
    <th>Percentage</th>
    </tr>
        """ % (odd_msg, format_decimal(daily_stats['alerts'], locale='en_US'))


        if 'rule' in daily_stats.keys():

            rule_dict = OrderedDict()
            for k, v in sorted(daily_stats['rule'].items()):
                rule_dict[k] = v

            for  l_rule, v_rule in sorted(rule_dict.items(), key=lambda x: x[1]):
                rule_pct = (v_rule*100)/daily_stats['alerts']
                if (odd_count %2) == 0:
                    odd_msg = ' class="odd"'
                else:
                    odd_msg = ""

                odd_count += 1

                buffer += """
                	    <tr %s>
	    <td>Total for Rule %s</td>
	    <td>%s</td>
	    <td>%s %%</td>
	    </tr>
                """ % (odd_msg, l_rule,  format_decimal(v_rule, locale='en_US'), "%.01f" % rule_pct)

        if (odd_count % 2) == 0:
            odd_msg =  ' class="odd"'
        else:
            odd_msg = ""

        buffer += """
        <tr %s>
<td>Total for all rules</td>
<td>%s</td>
<td>100%%</td>
</tr>
        """ % (odd_msg, format_decimal(daily_stats['alerts'], locale='en_US'))

        buffer += """
        </table>
</td></tr></table>
        """

        # Monthly stats
        if int(USER_day) == 0:
            buffer += """
                    <br /><br />
        <table align="center" summary="Total by day">
        <caption><strong>Total values per Day</strong></caption>
        <tr>
        <th>Day</th>
        <th>Alerts</th>
        <th>Alerts %</th>
        <th>Syscheck</th>
        <th>Syscheck %</th>
        <th>Firewall</th>
        <th>Firewall %</th>
        <th>Total</th>
        <th>Total %</th>
        </tr>

            """

            odd_count = 0
            odd_msg = ""

            for i in range(1, 32):
                # key は string であり、0 padding されていない
                if (str(i) in all_stats.keys()) and ('total' in all_stats[str(i)].keys()):
                    pass
                else:
                    continue

                d_total = int(all_stats[str(i)]['total'])
                d_alerts = int(all_stats[str(i)]['alerts'])
                d_syscheck = int(all_stats[str(i)]['syscheck'])
                d_firewall = int(all_stats[str(i)]['firewall'])

                total_pct = "%.01f" % (d_total*100/max(int(daily_stats['total']), 1))
                alerts_pct = "%.01f" % (d_alerts*100/max(int(daily_stats['alerts']), 1))
                syscheck_pct = "%.01f" % (d_syscheck*100/max(int(daily_stats['syscheck']), 1))
                firewall_pct = "%.01f" % (d_firewall*100/max(int(daily_stats['firewall']), 1))

                if (odd_count % 2) == 0:
                    odd_msg = ' class="odd"'
                else:
                    odd_msg = ""

                odd_count += 1

                buffer += """
            <tr %s>
            <td>Day %s</td>
            <td>%s</td>
            <td>%s %%</td>
            <td>%s</td>
            <td>%s %%</td>
            <td>%s</td>
            <td>%s %%</td>
            <td>%s</td>
            <td>%s %%</td>

            </tr>
                """ % (odd_msg, i,
                                format_decimal(d_alerts, locale='en_US'), alerts_pct,
                                format_decimal(d_syscheck, locale='en_US'), syscheck_pct,
                                format_decimal(d_firewall, locale='en_US'), firewall_pct,
                                format_decimal(d_total, locale='en_US'), total_pct

                                )

        # Daily stats
        else:
            buffer += """
                    <br /><br />
        <table align="center" summary="Total by hour">
        <caption><strong>Total values per hour</strong></caption>
        <tr>
        <th>Hour</th>
        <th>Alerts</th>
        <th>Alerts %</th>
        <th>Syscheck</th>
        <th>Syscheck %</th>
        <th>Firewall</th>
        <th>Firewall %</th>
        <th>Total</th>
        <th>Total %</th>
        </tr>
            """

            odd_count = 0
            odd_msg = ""

            for i in range(0, 24):
                if 'total_by_hour' in daily_stats.keys():
                    print ("OK")
                    print(daily_stats['total_by_hour'].keys())
                    if str(i) in daily_stats['total_by_hour'].keys():
                        pass
                    else:
                        print ("not found")
                        continue
                else:
                    continue

                print(" got it ?")

                hour_total = int(daily_stats['total_by_hour'][str(i)])
                hour_alerts = int(daily_stats['alerts_by_hour'][str(i)])
                hour_syscheck = int(daily_stats['syscheck_by_hour'][str(i)])
                hour_firewall = int(daily_stats['firewall_by_hour'][str(i)])

                total_pct = (hour_total*100)/max(daily_stats['total'], 1)
                alerts_pct = (hour_alerts*100)/max(daily_stats['alerts'], 1)
                syscheck_pct = (hour_syscheck*100)/max(daily_stats['syscheck'], 1)
                firewall_pct = (hour_firewall*100)/max(daily_stats['firewall'], 1)


                if (odd_count % 2) == 0:
                    odd_msg = ' class="odd"'
                else:
                    odd_msg = ""

                odd_count += 1

                buffer += """
            <tr.$odd_msg>
            <td>Hour %s</td>
            <td>%s</td>
            <td>%s %%</td>

            <td>%s</td>
            <td>%s %%</td>

            <td>%s</td>
            <td>%s %%</td>

            <td>%s</td>
            <td>%s %%</td>
            </tr>
                """ % (i,
                            format_decimal(hour_alerts, locale='en_US'), "%.01f" % alerts_pct,
                            format_decimal(hour_syscheck, locale='en_US'), "%.01f" % syscheck_pct,
                            format_decimal(hour_firewall, locale='en_US'), "%.01f" % firewall_pct,
                            format_decimal(hour_total, locale='en_US'), "%.01f" % total_pct
                        )




        buffer += "</table></div>"

        self.contents = buffer



    def _make_html(self):
        self.html = """\
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
%s
</head>

<body>
    <br/>
%s

<div id="container">
  <div id="content_box">
  <div id="content" class="pages">
  <a name="top"></a>

  <!-- BEGIN: content -->

  %s

  <!-- END: content -->

  <br /><br />
  <br /><br />
  </div>
  </div>

%s

</div>
</body>
</html>
""" % (View.HEAD, View.HEADER, self.contents, View.FOOTER)
        pass


    def getHtml(self):
        return self.html
