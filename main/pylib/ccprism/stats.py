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
            pass

        if is_post and ('month' in form):
            pass

        if is_post and ('year' in form):
            pass

        init_time = 0
        final_time = 0

        # Bulding stat time_stamp
        if USER_year and USER_month and USER_day:
            pass
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
        print(l_year_month)
        print(init_time)
        print(final_time)

        stats_list = os_lib_stats.os_getstats(ossec_handle, init_time, final_time)

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
