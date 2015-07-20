
import os,sys
import re

from flask import Flask, session, request, redirect, render_template, url_for
from flask import jsonify, make_response

from datetime import *
import time

import ossec_conf
import os_lib_handle
import os_lib_agent
#import os_lib_syscheck

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

        USER_level = ""

        USER_searchid = 0

        # Getting search id
        if self.is_post:
            str_searchid = self.request.form.get('searchid')
            if re.search("[a-z0-9]+", str_searchid):
                USER_searchid = int(str_searchid)


        # Reading user input -- being very careful parsing it
        if self.is_post:
            level = self.request.form.get('level')
            if level.isdigit() and (int(level) > 0) and (int(level) < 16):
                USER_level = level
                u_level = level

        print ("u_levels is %s" % u_level)

        buffer = ""

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

        # Level
        buffer += """<tr><td>Minimum level:</td><td><select name="level" class="formText">"""
        if int(u_level) == 1:
            buffer +=  '  <option value="1" selected="selected">All</option>'
        else:
            buffer += '   <option value="1">All</option>'

        print("u_levsl ---->>>>>>>> %s" % u_level)
        for l_counter in range(15, 1, -1):
            print (l_counter)
            if l_counter == int(u_level):
                print ("Match !!!!!")
                buffer += '   <option value="%s" selected="selected">%s</option>' % (l_counter, l_counter)
            else:
                buffer += '   <option value="%s">%s</option>' % (l_counter, l_counter)

        buffer += "</select>"



        # Final form
        buffer += """\
            <tr><td>
            <input type="submit" name="search" value="Search" class="button" />
        """

        buffer += """\
        </td></tr></table>
     <input type="hidden" name="searchid" value="'.$USER_searchid.'" />
     </form><br /> <br />
        """

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
