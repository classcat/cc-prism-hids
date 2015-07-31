##############################################################
# ClassCat(R) Prism for HIDS
#  Copyright (C) 2015 ClassCat Co.,Ltd. All rights reseerved.
##############################################################

# ===  Notice ===
# all python scripts were written by masao (@classcat.com)
#
# === History ===

#


import os,sys
import re
import traceback

from flask import Flask, session, request, redirect, render_template, url_for
from flask import jsonify, make_response

from datetime import *
import time
import uuid
import hashlib

from collections import OrderedDict

from babel.numbers import format_decimal

import os_lib_handle
#import os_lib_agent
#import os_lib_alerts
import os_lib_stats

from ossec_categories import global_categories
from ossec_formats import log_categories

from .view import View

class Stats(View):

    def __init__(self, request, conf):
        super().__init__(request, conf)

        self._make_contents()
        self._make_html()


    def _make_contents(self):
        req = self.request
        conf = self.conf

        form = req.form

        is_post = self.is_post
        is_lang_ja = self.is_lang_ja

        # Starting handle
        if not conf.check_dir():
            if is_lang_ja:
                buffer += "ossec ディレクトリにアクセスできません。\n"
            else:
                buffer += "Unable to access ossec directory.\n"
            self.contents = buffer
            return

        # Current date values (day : 05, month : 07, year : 2015)
        curr_time = int(time.time())
        curr_day =  int(datetime.fromtimestamp(curr_time).strftime("%d")) # 0 padding を回避
        curr_month = datetime.fromtimestamp(curr_time).strftime("%m")
        curr_year = datetime.fromtimestamp(curr_time).strftime("%Y")

        # Getting user values
        USER_day = None
        USER_month = None
        USER_year = None

        if is_post and ('day' in form.keys()):
            strday = form.get('day')
            if strday.isdigit():
                if (int(strday) >= 0) and (int(strday) <=31 ):
                    USER_day = strday
                    # USER_day = "%02d" % int(strday)  # TODO : キーをどうするか

        if is_post and ('month' in form.keys()):
            strmonth = form.get('month')
            if strmonth.isdigit():
                if (int(strmonth) > 0) and (int(strmonth) <=12):
                    USER_month = strmonth

        if is_post and ('year' in form.keys()):
            stryear = form.get('year')
            if stryear.isdigit():
                if (int(stryear) >= 1) and (int(stryear) <= 3000):
                    USER_year = stryear

        init_time = 0
        final_time = 0

        # Bulding stat time_stamp
        if (USER_year is not None) and (USER_month is not None) and (USER_day is not None):
            # Stat for whole month
            if int(USER_day) == 0:
                init_time = int(time.mktime((int(USER_year), int(USER_month), 1, 0, 0, 0, 0, 0, -1)))
                final_time = int(time.mktime((int(USER_year), int(USER_month) + 1, 0, 0, 0, 0, 0, 0, -1)))
                # 2015-12-01 00:00:00
                # 2015-12-31 00:00:00
                # print(datetime.fromtimestamp(init_time))
                # print(datetime.fromtimestamp(final_time))

            else:
                init_time = int(time.mktime((int(USER_year), int(USER_month), int(USER_day), 0, 0, 0, 0, 0, -1)))
                final_time = int(time.mktime((int(USER_year), int(USER_month), int(USER_day), 0, 0, 10, 0, 0, -1)))

                # Getting valid formated day
                #$USER_day = date('d',$init_time);

                # 0 padding は回避

        else:
            init_time = curr_time - 1
            final_time = curr_time

            # Setting user values
            USER_month = curr_month
            USER_day = curr_day
            USER_year = curr_year

        # print("USER_day %s USER_month %s USER_year %s" % (USER_day, USER_month, USER_year))
        # get : USER_day 01 USER_month 08 USER_year 2015
        # post : USER_day 1 USER_month 8 USER_year 2015

        buffer = ""

        # Day option
        if is_lang_ja:
            buffer += "<h2>統計情報オプション</h2><br />\n"
        else:
            buffer += "<h2>Stats options</h2><br />\n"

        msg_day = "Day:"
        if is_lang_ja:
            msg_day = "日:"
        buffer += """\
        <form name="dosearch" method="post" action="stats">

%s  <select name="day" class="formSelect">
    <option value="0">All days</option>
        """ % (msg_day)

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

        msg_month = "Month:"
        if is_lang_ja:
            msg_month = "月:"

        buffer += """ %s <select name="month" class="formSelect">""" % (msg_month)

        mnt_ct = 1
        for tmp_month, tmp_month_v in months.items():
            if int(USER_month) == mnt_ct:
                buffer += """    <option value="%s" selected="selected">%s</option>""" % (mnt_ct, tmp_month)
            else:
                buffer += """    <option value="%s">%s</option>""" % (mnt_ct, tmp_month)

            mnt_ct += 1

        buffer += "</select>"

        # Year
        msg_year = "Year:"
        msg_change_options = "Change options"
        if is_lang_ja:
            msg_year = "年:"
            msg_change_options = "オプション変更"

        buffer += """ %s <select name="year" class="formSelect">
        <option value="%s" selected="selected">%s</option>
        <option value="%s">%s</option>
        <option value="%s">%s</option>
        </select> <button type="submit" name="Stats" value="Change options" class="button" />%s</button></form>""" % (msg_year, curr_year, curr_year, int(curr_year) - 1, int(curr_year) -1, int(curr_year) -2, int(curr_year) -2, msg_change_options)

        #
        # Getting daily stats
        #

        l_year_month = datetime.fromtimestamp(init_time).strftime("%Y/%b")  #  2015/Jul

        # print ("INIT_TIME")
        # print (init_time)
        # print(final_time)
        # print (datetime.fromtimestamp(init_time).strftime("%Y/%m/%d %H:%M:%S"))
        # print (datetime.fromtimestamp(final_time).strftime("%Y/%m/%d %H:%M:%S"))

        # 7/1 指定の場合
        # 1435676400
        # 1435676410
        # 2015/07/01 00:00:00
        # 2015/07/01 00:00:10

        # 7/17 指定の場合
        # 2015/07/17 00:00:00
        # 2015/07/17 00:00:10

        # 7/All
        # 1435676400
        # 1438268400
        # 2015/07/01 00:00:00
        # 2015/07/31 00:00:00

        stats_list = os_lib_stats.os_getstats(conf, init_time, final_time)

        # print ("stats_list")
        #print (stats_list)
        # print ("USER_day %s"  % USER_day) # 0 padding  されていない

        daily_stats = OrderedDict()
        all_stats = None

        if l_year_month in stats_list.keys():
            #for k in stats_list[l_year_month].keys():
            #    print ("key is : %s" %k)
            if str(USER_day) in stats_list[l_year_month].keys():
                daily_stats = stats_list[l_year_month][str(USER_day)]
                all_stats = stats_list[l_year_month]

        if not 'total' in daily_stats.keys():
            buffer += """<br/>
                <b class="red">No stats available.</b>
            """
            self.contents += buffer
            return

        else:
            buffer += "<br />"

        # Day 0 == month stats
        if int(USER_day) == 0:
            if is_lang_ja:
                buffer += "<h2>統計情報 for: <b id='blue'>%s</b></h2><br />\n" % l_year_month
            else:
                buffer += "<h2>Ossec Stats for: <b id='blue'>%s</b></h2><br />\n" % l_year_month
        else:
            if is_lang_ja:
                buffer += "<h2>統計情報 for: <b id='blue'>%s/%02d</b> </h2><br /><br />\n\n" % (l_year_month, int(USER_day))
            else:
                buffer += "<h2>Ossec Stats for: <b id='blue'>%s/%02d</b> </h2><br /><br />\n\n" % (l_year_month, int(USER_day))

        if is_lang_ja:
            buffer += "<b>総計</b>: " + format_decimal(daily_stats['total'], locale='en_US')+ "<br/>"
            buffer += "<b>Alerts</b>: " + format_decimal(daily_stats['alerts'], locale='en_US') + "<br/>"
            buffer += "<b>整合性チェック</b>: " + format_decimal(daily_stats['syscheck'], locale='en_US') + "<br/>"
            buffer += "<b>ファイアウォール</b>: " + format_decimal(daily_stats['firewall'], locale='en_US') + "<br/>"
        else:
            buffer += "<b>Total</b>: " + format_decimal(daily_stats['total'], locale='en_US')+ "<br/>"
            buffer += "<b>Alerts</b>: " + format_decimal(daily_stats['alerts'], locale='en_US') + "<br/>"
            buffer += "<b>Syscheck</b>: " + format_decimal(daily_stats['syscheck'], locale='en_US') + "<br/>"
            buffer += "<b>Firewall</b>: " + format_decimal(daily_stats['firewall'], locale='en_US') + "<br/>"

        if int(USER_day) != 0:
            h_avg = int(daily_stats['total']) / 24.0
            if is_lang_ja:
                buffer += "<b>平均</b>: " + "%.02f" % h_avg + " イベント / 時間"
            else:
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



    def x_make_html(self):
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
