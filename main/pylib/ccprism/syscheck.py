
import os,sys

from flask import Flask, session, request, redirect, render_template, url_for
from flask import jsonify, make_response

import datetime
import ossec_conf
import os_lib_handle
import os_lib_syscheck

class SysCheck(object):
    HEAD = """\
	<title>OSSEC Web Interface - Open Source Security</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <link rel="shortcut icon" href="static/css/images/favicon.ico" />
    <link rel="stylesheet" type="text/css" media="all"  href="static/css/cal.css" title="css/cal.css" />
    <script type="text/javascript" src="static/js/calendar.js"></script>
    <script type="text/javascript" src="static/js/calendar-en.js"></script>
    <script type="text/javascript" src="static/js/calendar-setup.js"></script>
    <script type="text/javascript" src="static/js/prototype.js"></script>
    <script type="text/javascript" src="static/js/hide.js"></script>
    <link rel="stylesheet" rev="stylesheet"   href="static/css/css.css" type="text/css" />
"""

    HEADER = """\
<!-- OSSEC UI header -->

<div id="header">
  <div id="headertitle">
      <table>
      <tr>
        <td>
          &nbsp;&nbsp;<a href="http://www.ossec.net/">
          <img width="191" height="67" src="static/img/ossec_webui.png" title="Go to OSSEC.net" alt="Go to OSSEC.net"/></a>
        </td>

        <td>
          <img width="107" height="38" src="static/img/webui.png"/><br>&nbsp;&nbsp; <i>Version 0.8</i>
        </td>
      </tr>
      </table>
  </div>

  <ul id="nav">
  <li><a href="main" title="Main">Main</a></li>
  <li><a href="search" title="Search events">Search</a></li>
  <li><a href="syscheck" title="Integrity checking">Integrity checking</a></li>
  <li><a href="stats" title="Stats">Stats</a></li>
  <li><a href="help" title="Help">About</a></li>
  </ul>
</div>

<!-- END OF HEADER -->
"""

    FOOTER = """\
<!-- OSSEC UI footer -->

<div id="footer">
    <p class="center">All Content &copy; 2006 - 2013 <a href="http://www.trendmicro.com"><font color="red"><b>Trend Micro</b></font></a>. All rights reserved</p>
</div>

<!-- END of FOOTER -->
"""

    def __init__(self, request):
        self.request = request

        self.html = ""
        self.contents=  ""

        self._make_contents()
        self._make_html()

    def _make_contents(self):

        if request.method == 'POST':
            pass

        buffer = ""

        # Starting handle
        ossec_handle = os_lib_handle.os_handle_start(ossec_conf.ossec_dir)

        # Getting syscheck information
        syscheck_list = os_lib_syscheck.os_getsyscheck(ossec_handle)

        # Dumping database
        if request.method == 'POST':
            pass

        buffer += "<br /><h2>Latest modified files (for all agents): </h2>\n\n"

        last_mod_date = ""
        sk_count = 0

        for syscheck in syscheck_list['global_list']['files']:
            sk_count += 1

            ffile_name = ""
            ffile_name2 = ""

            ffile_name = syscheck['sk_file_name']

            # Setting the database
            ts = int(syscheck['time_stamp'])
            dt = datetime.datetime.fromtimestamp(ts).strftime("%m/%d/%Y")
            if last_mod_date != dt:
                last_mod_date = dt
                buffer += "<br/><b>%s</b><br/>" % last_mod_date

            # ts = datetime.datetime.fromtimestamp(int(syscheck['time_stamp'])).strftime("%m/%d/%Y %H:%M:%S")


            buffer += """
               <span id="togglesk%s">
               <a  href="#" class="bluez" title="Expand %s"
               onclick="ShowSection(\'sk%s\');return false;"><span class="bluez">+
               %s</span></a><br />
               </span>
            """ % (sk_count, ffile_name, sk_count, ffile_name)

            pass

        syscheck_count = 0
        syscheck_list2 = []
        # {'time_stamp':time_stamp, '_name':_name, 'sk_file_name':sk_file_name}
        for syscheck in syscheck_list['global_list']['files']:
            ts = datetime.datetime.fromtimestamp(int(syscheck['time_stamp'])).strftime("%m/%d/%Y %H:%M:%S")
            syscheck_list2.append({'id':syscheck_count, 'ts':ts, 'name':syscheck['_name'], 'filename':syscheck['sk_file_name']})
            syscheck_count += 1
        pass

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
""" % (SysCheck.HEAD, SysCheck.HEADER, self.contents, SysCheck.FOOTER)
        pass

    def getHtml(self):
        return self.html
        pass
