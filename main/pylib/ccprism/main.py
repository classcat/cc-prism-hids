
##############################################################
# ClassCat(R) Prism for HIDS
#  Copyright (C) 2015 ClassCat Co.,Ltd. All rights reseerved.
##############################################################

# ===  Notice ===
# all python scripts were written by masao (@classcat.com)
#
# === History ===
# 29-jul-15 : fixed for beta.
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
        if is_lang_ja:
            buffer += "<h2>利用可能なエージェント:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</h2><br />\n\n"
        else:
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
        if is_lang_ja:
            buffer += "<td valign='top' width='55%'><h2>最新の変更ファイル: </h2><br />\n\n"
        else:
            buffer += "<td valign='top' width='55%'><h2>Latest modified files: </h2><br />\n\n"

        syscheck_list = None
        is_error_syscheck = False
        try:
            syscheck_list = os_lib_syscheck.os_getsyscheck(conf)
        except Exception as e:
            is_error_syscheck = True
            traceback.print_exc(file=sys.stdout)
            buffer += """<span style="color:red;"><b>Error : </b> %s</span>""" % e

        if is_error_syscheck:
            pass

        elif (not 'global_list' in syscheck_list.keys()) or (not 'files' in syscheck_list['global_list']):
            buffer += """<ul class="ulsmall bluez">
                No integrity checking information available.<br />
                Nothing reported as changed.
                </ul>"""

        else:
            sk_count = 0

            for syscheck in syscheck_list['global_list']['files']:
                sk_count += 1

                if sk_count > 10:
                #if sk_count > (agent_count +4):
                    break

                # {'sk_file_name': '/etc/resolv.conf', '_name': 'ossec-server', 'time_stamp': '1437629895'}

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
        if is_lang_ja:
            buffer += "<h2>最新の Alert イベント</h2><br />\n"
        else:
            buffer += "<h2>Latest events</h2><br />\n"

        alert_list = None
        is_error_alerts = False
        try:
            alert_list = os_lib_alerts.os_getalerts(conf, 0, 0, 30)  # init_time, final_time, max_count

        except Exception as e:
            is_error_alert_list = True
            traceback.print_exc(file=sys.stdout)
            buffer += """<span style="color:red;"><b>Error : </b> %s</span>""" % e

            self.contents = buffer
            return

        alert_count = alert_list.size() - 1
        alert_array  = alert_list.alerts()

        lang = "en"
        if is_lang_ja:
            lang = "ja"
        while alert_count >= 0:
            buffer += alert_array[alert_count].toHtml(lang)
            alert_count -= 1


        self.contents = buffer


### End of Script ###
