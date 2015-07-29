
##############################################################
# ClassCat(R) Prism for HIDS
#  Copyright (C) 2015 ClassCat Co.,Ltd. All rights reseerved.
##############################################################

# ===  Notice ===
# all python scripts were written by masao (@classcat.com)
#
# === History ===
#
#

import os,sys
import re
import traceback

from flask import Flask, session, request, redirect, render_template, url_for
from flask import jsonify, make_response

from datetime import *
#import time
#import uuid
#import hashlib

from collections import OrderedDict

import os_lib_agent
import os_lib_alerts
import os_lib_syscheck

from .view import View

class Main(View):

    def __init__(self, request, conf):
        super().__init__(request, conf)

        self._make_contents()
        self._make_html()


    def _make_contents(self):
        req    = self.request
        conf  = self.conf

        form  = req.form

        is_post = self.is_post
        is_lang_ja = self.is_lang_ja

        buffer = ""

        if not conf.check_dir():
            if is_lang_ja:
                buffer += "ossec ディレクトリにアクセスできません。\n"
            else:
                buffer += "Unable to access ossec directory.\n"
            self.contents = buffer
            return

        # Getting all agents - No error happens.
        agent_list = os_lib_agent.os_getagents(conf)

        # Printing current date
        if is_lang_ja:
            buffer += """<div class="smaller2">現在時刻 : <b>%s</b></div><br />""" %  datetime.now().strftime("%m/%d/%Y (%a) %H:%M:%S")
        else:
            buffer += """<div class="smaller2">%s</div><br />""" %  datetime.now().strftime("%m/%d/%Y (%a) %H:%M:%S")

        # Geteting syscheck information
        # 後で呼ばれる
        #syscheck_list = os_lib_syscheck.os_getsyscheck(conf)

        #syscheck_list = os_lib_syscheck.os_getsyscheck(ossec_handle)


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
        syscheck_list = None
        is_error_syscheck = False
        try:
            syscheck_list = os_lib_syscheck.os_getsyscheck(conf)
        except Exception as e:
            is_error_syscheck = True
            traceback.print_exc(file=sys.stdout)
            buffer += """<span style="color:red;"><b>Error : </b> %s</span>""" % e
#                syscheck_list = os_lib_syscheck.os_getsyscheck(ossec_handle)


        #if (len(syscheck_list) == 0) or (len(syscheck_list['global_list']) == 0):
        #    pass
        if ((not is_error_syscheck) and 'global_list' in syscheck_list.keys()) and ('files' in syscheck_list['global_list']):
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
        alert_list = os_lib_alerts.os_getalerts(conf, 0, 0, 30)
#                alert_list = os_lib_alerts.os_getalerts(ossec_handle, 0, 0, 30)


        buffer += "<h2>Latest events</h2><br />\n"

        alert_count = alert_list.size() - 1
        alert_array  = alert_list.alerts()

        while alert_count >= 0:
            buffer += alert_array[alert_count].toHtml()
            alert_count -= 1


        self.contents = buffer
