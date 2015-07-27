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
import os_lib_syscheck

from ossec_categories import global_categories
from ossec_formats import log_categories

from .view import View

class Main(View):

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
        if ossec_handle is None:
            print("Unable to access ossec directory.\n")
            return(1)

        # Getting all agents
        agent_list = os_lib_agent.os_getagents(ossec_handle)

        buffer = ""

        # Printing current date
        buffer += """<div class="smaller2">%s</div><br />""" %  datetime.now().strftime("%m/%d/%Y %H:%M:%S")

        # Geteting syscheck information
        syscheck_list = os_lib_syscheck.os_getsyscheck(ossec_handle)

        buffer += '<table width="95%"><tr><td width="45%" valign="top">'

        # Available agents
        buffer += "<h2>Available&nbsp;agents:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</h2><br />\n\n"

        # Agent count for java script
        agent_count = 0

        # Looping all agents
        for agent in agent_list:
            atitle = ""
            aclass = ""
            amsg = ""

            # if agent is connected
            if agent['connected']:
                atitle = "Agent active"
                aclass = 'class="bluez"'
            else:
                atitle = "Agent Inactive"
                aclass = 'class="red"'
                amsg = " -inactive"

            buffer += """
<span id="toggleagt%s">
    <a  href="#" %s title="'%s" onclick="ShowSection('agt%s');return false;"><span class="bluez">+%s (%s)%s</span></a><br />
</span>
""" % (agent_count, aclass, atitle, agent_count, agent['name'], agent['ip'], amsg)

            buffer += """
<div id="contentagt%s" style="display: none">

    <a  href="#" %s title="%s"  onclick="HideSection('agt%s');return false;">-%s (%s)%s</a><br />
<div class="smaller">
    &nbsp;&nbsp;<b>Name:</b> %s<br />
    &nbsp;&nbsp;<b>IP:</b> %s<br />
    &nbsp;&nbsp;<b>Last keep alive:</b> %s<br />
    &nbsp;&nbsp;<b>OS:</b> %s<br />
</div>
</div>
            """ % (agent_count, aclass, atitle, agent_count, agent['name'], agent['ip'], amsg,
                        agent['name'], agent['ip'],
                        datetime.fromtimestamp(agent['change_time']).strftime('%m/%d/%Y %H:%M:%S'),
                        agent['os']
            )

            buffer += "\n"
            agent_count += 1

        buffer += "\n"

        # Last modified files
        buffer += "<td valign='top' width='55%'><h2>Latest modified files: </h2><br />\n\n"
        syscheck_list = os_lib_syscheck.os_getsyscheck(ossec_handle)

        #if (len(syscheck_list) == 0) or (len(syscheck_list['global_list']) == 0):
        #    pass
        if ('global_list' in syscheck_list.keys()) and ('files' in syscheck_list['global_list']):
            sk_count = 0

            for syscheck in syscheck_list['global_list']['files']:
                sk_count += 1

                if sk_count > 10:
                #if sk_count > (agent_count +4):
                    break

                # {'sk_file_name': '/etc/resolv.conf', '_name': 'ossec-server', 'time_stamp': '1437629895'}

                print (syscheck)

                ffile_name = syscheck['sk_file_name']

                buffer += """
<span id="togglesk%s">
    <a  href="#" class="bluez" title="Expand %s"  onclick="ShowSection('sk%s');return false;"><span class="bluez">+%s</span></a><br />
 </span>
                """ % (sk_count, ffile_name, sk_count, ffile_name)


                buffer += """
<div id="contentsk%s" style="display: none">
    <a  href="#" title="Hide %s"  onclick="HideSection('sk%s');return false;">-%s</a>
<br />
<div class="smaller">
&nbsp;&nbsp;<b>File:</b> %s<br />
&nbsp;&nbsp;<b>Agent:</b> %s<br />
&nbsp;&nbsp;<b>Modification time:</b> %s<br />
</div>

</div>
""" % (sk_count, ffile_name, sk_count, ffile_name,
            ffile_name, syscheck['_name'],
            datetime.fromtimestamp(int(syscheck['time_stamp'])).strftime('%m/%d/%Y %H:%M:%S')
            )

        buffer += "</td></tr></table>"
        buffer += "<br /> <br />\n"

        # Getting last alerts
        alert_list = os_lib_alerts.os_getalerts(ossec_handle, 0, 0, 30)

        buffer += "<h2>Latest events</h2><br />\n"

        alert_count = alert_list.size() - 1
        alert_array  = alert_list.alerts()

        while alert_count >= 0:
            buffer += alert_array[alert_count].toHtml()
            alert_count -= 1


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
