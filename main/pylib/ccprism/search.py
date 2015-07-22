
import os,sys
import re

from flask import Flask, session, request, redirect, render_template, url_for
from flask import jsonify, make_response

from datetime import *
import time
import uuid
import hashlib

import ossec_conf
import os_lib_handle
import os_lib_agent
import os_lib_alerts
#import os_lib_syscheck

from ossec_categories import global_categories
from ossec_formats import log_categories

from .view import View

class Search(View):

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

        # Starting handle
        ossec_handle = os_lib_handle.os_handle_start(ossec_conf.ossec_dir)

        # Iniitializing some variables
        u_final_time = int(time.time())
        #u_final_time = int(time.mktime(datetime.now().timetuple()))
        u_init_time   = int(u_final_time  - ossec_conf.ossec_search_time) # 14400 = 3600 * 4

        u_level = ossec_conf.ossec_search_level
        u_pattern = ""
        u_rule = ""
        u_srcip = ""
        u_user = ""
        u_location = ""

        USER_final = 0
        USER_init = 0
        USER_level = ""

        USER_pattern = None
        LOCATION_pattern = None
        USER_group = None
        USER_log = None
        USER_rule = None
        USER_srcip = None
        USER_user = None

        USER_page = 1
        USER_searchid = 0
        USER_monitoring = 0
        used_stored = 0

        # Getting search id
        if self.is_post:
            str_searchid = self.request.form.get('searchid')
            if re.search("[a-z0-9]+", str_searchid):
                print(str_searchid)
                USER_searchid = str_searchid # It might be hex. dont use int().

        if self.is_post:
            str_monitoring = self.request.form.get('monitoring')
            if str_monitoring and (int(str_monitoring) == 1):
                pass

        # Reading user input -- being very careful parsing it

        # Initial Date
        datepattern = "^([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2})$";
        if self.is_post:
            str_initdate = self.request.form.get('initdate')
            mobj = re.search(datepattern, str_initdate)
            if mobj:
                year = int(mobj.group(1))
                month = int(mobj.group(2))
                day = int(mobj.group(3))
                hour = int(mobj.group(4))
                minute = int(mobj.group(5))

                USER_init = int(time.mktime((year, month, day, hour, minute, 0, 0, 0, -1)))
                u_init_time = USER_init
                # to check :
                # print(datetime.fromtimestamp(u_init_time))

        # Final Date
        if self.is_post:
            str_finaldate = self.request.form.get('finaldate')
            mobj = re.search(datepattern, str_finaldate)
            if mobj:
                year = int(mobj.group(1))
                month = int(mobj.group(2))
                day = int(mobj.group(3))
                hour = int(mobj.group(4))
                minute = int(mobj.group(5))
                USER_final = int(time.mktime((year, month, day, hour, minute, 0, 0, 0, -1)))
                u_final_time = USER_final

        # Level
        if self.is_post:
            level = self.request.form.get('level')
            if level and level.isdigit() and (int(level) > 0) and (int(level) < 16):
                USER_level = level
                u_level = level

        # Group pattern

        # Rule pattern

        # Maximum number of alerts

        buffer = ""

        # Getting search id -- should be enough to avoid duplicates
        if self.is_post:
            print (request.form)
            # ImmutableMultiDict([('initdate', '2015-07-21 15:00'), ('level', '3'), ('search', 'Search'), ('monitoring', '0'), ('finaldate', '2015-07-21 19:00'), ('searchid', '0')])
            if 'search' in request.form:
                # Creating new search id
                #  (in php)       $USER_searchid = md5(uniqid(rand(), true));
                m = hashlib.md5()
                m.update(str(uuid.uuid4()).encode('UTF-8'))
                print(m.hexdigest())
                USER_searchid = m.hexdigest()
                USER_page = 1

            else:
                buffer += "<b class='red'>Invalid search. </b><br />\n"
                self.contents = buffer
                return

        # Printing current date
        buffer += """<div class="smaller2">%s<br/>""" % datetime.now().strftime("%m/%d/%Y %H:%M:%S")
        if USER_monitoring == 1:
            buffer +=  """ -- Refreshing every %s secs</div><br />""" % ossec_conf.ossec_refresh_time
        else:
            buffer += "</div><br/>"

        # Getting all agents
        agent_list = os_lib_agent.os_getagents(ossec_handle)


        buffer += "<h2>Alert search options:</h2>\n"

        # Search forms
        buffer += """\
        <form name="dosearch" method="post" action="/search">
        <table><tr valign="top">
        <td><input type="radio" name="monitoring" value="0" checked="checked"/></td>
        <td>From: &nbsp;<input type="text" name="initdate"   id="i_date_a" size="17" value="%s"  maxlength="16"  class="formText" />
            <img src="static/img/calendar.gif" id="i_trigger" title="Date selector"  alt="Date selector" class="formText" />
        </td>
        <td>&nbsp;&nbsp;To: &nbsp;<input type="text" name="finaldate" id="f_date_a" size="17" value="%s"  maxlength="16"  class="formText" />
            <img src="static/img/calendar.gif" id="f_trigger" title="Date selector" alt="Date selector" class="formText" />
        </td>
        </tr>
        """ % (
                    datetime.fromtimestamp(u_init_time).strftime("%Y-%m-%d %H:%M"),
                    datetime.fromtimestamp(u_final_time).strftime("%Y-%m-%d %H:%M")
                )



        buffer += """<tr><td><input type="radio" name="monitoring" value="1" '.$rt_sk.'/></td>
              <td>Real time monitoring</td></tr>
              </table>
              <br />
              <table>
              """

        # Minimum Level
        buffer += """<tr><td>Minimum level:</td><td><select name="level" class="formText">"""
        if int(u_level) == 1:
            buffer +=  '  <option value="1" selected="selected">All</option>'
        else:
            buffer += '   <option value="1">All</option>'

        for l_counter in range(15, 1, -1):
            print (l_counter)
            if l_counter == int(u_level):
                print ("Match !!!!!")
                buffer += '   <option value="%s" selected="selected">%s</option>' % (l_counter, l_counter)
            else:
                buffer += '   <option value="%s">%s</option>' % (l_counter, l_counter)

        buffer += "</select>"

        # Category
        buffer += """</td><td>
        Category: </td><td><select name="grouppattern" class="formText">"""
        buffer += '<option value="ALL" class="bluez">All categories</option>'
        for _cat_name, _cat in global_categories.items():
            sl = ""
            for cat_name, cat_val  in _cat.items():
                if cat_name.find("(all)") != -1:
                    buffer += """<option class="bluez" %s value="%s">%s</option>""" % (sl, cat_val, cat_name)
                else:
                    buffer += """<option value="%s" %s> &nbsp; %s</option>""" % (cat_val, sl, cat_name)

        buffer += '</select>'

        # Str pattern
        buffer += """</td></tr><tr><td>
            Pattern: </td><td><input type="text" name="strpattern" size="16"
            value="%s" class="formText" /></td>""" % u_pattern

        # Log formats
        buffer += '<td>Log formats: </td><td><select name="logpattern" class="formText">'
        buffer += '<option value="ALL" class="bluez">All log formats</option>'

        for _cat_name, _cat in log_categories.items():
            print (_cat_name)
            #print (_cat)
            for cat_name, cat_val  in _cat.items():
                print (cat_name)
                print (cat_val)
                sl = ""
                if USER_log == cat_val:
                    sl = ' selected="selected"'
                if cat_name.find("(all)") != -1:
                    buffer += """<option class="bluez" %s value="%s">%s</option>"""% (sl, cat_val, cat_name)
                else:
                    buffer += """<option value="%s" %s> &nbsp; %s</option>""" % (cat_val, sl, cat_name)

        buffer += '</select>'

        # Srcip pattern

        # Rule pattern

        # Location

        # Max alerts
        buffer += """'</td></tr><tr><td>
            Max Alerts:</td>
            <td><input type="text" name="max_alerts_per_page" size="8" value="%s" class="formText" /></td></tr>
        """ % ossec_conf.ossec_max_alerts_per_page

        # Final form
        buffer += """\
            <tr><td>
            <input type="submit" name="search" value="Search" class="button" />
        """

        buffer += """\
        </td></tr></table>
     <input type="hidden" name="searchid" value="%s" />
     </form><br /> <br />
        """ % USER_searchid

        # Java script for date
        buffer += """\
<script type="text/javascript">
Calendar.setup({
button          :   "i_trigger",
inputField     :    "i_date_a",
ifFormat       :    "%Y-%m-%d %H:%M",
showsTime      :    true,
timeFormat     :    "24"
});
Calendar.setup({
button          :   "f_trigger",
inputField     :    "f_date_a",
ifFormat       :    "%Y-%m-%d %H:%M",
showsTime      :    true,
timeFormat     :    "24"
});
</script>

        """

        buffer += "<h2>Results:</h2>\n"

        if (not USER_init) or (not USER_final) or (not USER_level):
            buffer += "<b>No search performced.</b><br/>\n"
            self.contents = buffer
            return

        output_list = None

        # Getting stored alerts
        if self.is_post:
            str_search = self.request.form.get("search")
            print("search" + str_search)
            if str_search != "Search":
                #output_list = os_getstoredalerts(ossec_handle, USER_searchied)
                used_stored = 1
            else:
                # Getting alerts
                output_list = os_lib_alerts.os_searchalerts(ossec_handle,
                                    USER_searchid,
                                    USER_init,
                                    USER_final,
                                    ossec_conf.ossec_max_alerts_per_page,
                                    USER_level,
                                    USER_rule,
                                    LOCATION_pattern,
                                    USER_pattern,
                                    USER_group,
                                    USER_srcip,
                                    USER_user,
                                    USER_log)

        if (output_list is None) or (output_list[1] is None):
            if used_stored == 1:
                buffer += "<b class='red'>Nothing returned (search expired). </b><br />\n"
            else:
                buffer += "<b class='red'>Nothing returned. </b><br />\n"

            self.contents = buffer
            return

        # Checking for no return
        if not 'count' in output_list[0]:
            buffer += "<b class='red'>Nothing returned. </b><br />\n"
            self.contents = buffer
            return

        # Checking maximum page size
        if USER_page >= output_list[0]['pg']:
            USER_page = output_list[0]['pg']

        # Page 1

        buffer += "<b>Total alerts found: </b>%s<br />" % output_list[0]['count']

        print(output_list)


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
