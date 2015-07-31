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
import datetime

from flask import Flask, session, request, redirect, render_template, url_for
from flask import jsonify, make_response

import os_lib_handle
import os_lib_syscheck

from .view import View

class SysCheck(View):

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

        # Initializing variables
        u_agent = "ossec-server"
        u_file = ""
        USER_agent = None
        USER_file = None

        # Getting user patterns
        strpattern = "^[0-9a-zA-Z._^ -]{1,128}$"
        if is_post and ('agentpattern' in form.keys()):
            agentpattern = form.get('agentpattern')
            if re.search(strpattern, agentpattern):
                USER_agent = agentpattern
                u_agent = USER_agent

        if is_post and ('filepattern' in form.keys()):
            filepattern = form.get('filepattern')
            if re.search(strpattern, filepattern):
                u_file = USER_file

        buffer = ""

        # Starting handle
        if not conf.check_dir():
            if is_lang_ja:
                buffer += "ossec ディレクトリにアクセスできません。\n"
            else:
                buffer += "Unable to access ossec directory.\n"
            self.contents = buffer
            return

        # Getting syscheck information
        syscheck_list = None
        is_error_syscheck = False
        try:
            syscheck_list = os_lib_syscheck.os_getsyscheck(conf)
        except Exception as e:
            is_error_syscheck = True
            traceback.print_exc(file=sys.stdout)

            buffer += """<span style="color:red;"><b>Error : </b> %s</span>""" % e
            self.contents = buffer
            return

        # Creating form
        msg_agent_name = "Agent name:"
        if is_lang_ja:
            msg_agent_name = "エージェント名:"
        buffer += """\
        <form name="dosearch" method="post" action="syscheck">
        <table><tr valign="top">
        <td>%s </td>
        <td><select name="agentpattern" class="formText">
""" % (msg_agent_name)

        for agent in syscheck_list.keys():   # global_list, ossec-server
            sl = ""
            if agent == "global_list":
                continue
            elif u_agent == agent:
                sl = ' selected ="selected"'

            buffer += """<option value="%s" %s> &nbsp; %s</option>""" % (agent, sl, agent)

        buffer += "</select></td>"

        msg_dump_db = "Dump database"
        if is_lang_ja:
            msg_dump_db = "&nbsp;データベースのダンプ&nbsp;"
        buffer += """    <td>&nbsp;<button type="submit" name="ss" value="Dump database" class="button"/>%s</button>""" % (msg_dump_db)
        #buffer += """    <td><input type="submit" name="ss" value="Dump database" class="button"/>"""

        if USER_agent is not None:
            buffer += """&nbsp; &nbsp;<a class="bluez" href="syscheck"> &lt;&lt;back</a>"""

        buffer += """\
            </td>
    </tr></table>
    </form>
    """

        # Dumping database
        if is_post and ('ss' in form.keys()):
            if (form.get('ss') == "Dump database") and (USER_agent is not None):
                try:
                    dump_buffer = os_lib_syscheck.os_syscheck_dumpdb(conf, USER_agent)
                except Exception as e:
                    traceback.print_exc(file=sys.stdout)
                    buffer += """<br><span style="color:red;"><b>Unexpected Error</b> : %s</span><br/>""" % e
                    self.contents = buffer
                    return

                self.contents = buffer + dump_buffer
                return

        buffer += "<br /><h2>Latest modified files (for all agents): </h2>\n\n"

        last_mod_date = ""
        sk_count = 0

        # in case NO syscheck file, { 'global_list' : {} } が返るので、'files' は当然ない
        for syscheck in syscheck_list['global_list']['files']:
            sk_count += 1

            ffile_name = ""
            ffile_name2 = ""

            ffile_name = syscheck['sk_file_name']

            # Setting the database
            ts = int(syscheck['time_stamp'])
            dt   = datetime.datetime.fromtimestamp(ts).strftime("%m/%d/%Y")
            dt2 = datetime.datetime.fromtimestamp(ts).strftime("%m/%d/%Y %H:%M:%S")
            if last_mod_date != dt:
                last_mod_date = dt
                buffer += "<br/><b>%s</b><br/>" % last_mod_date

            # ts = datetime.datetime.fromtimestamp(int(syscheck['time_stamp'])).strftime("%m/%d/%Y %H:%M:%S")

            buffer += """\
               <span id="togglesk%s">
               <a  href="#" class="bluez" title="Expand %s"
               onclick="ShowSection(\'sk%s\');return false;"><span class="bluez">+
               %s</span></a><br />
               </span>
            """ % (sk_count, ffile_name, sk_count, ffile_name)

            buffer += """\
                <div id="contentsk%d" style="display: none">

               <a  href="#" title="Hide %s"
               onclick="HideSection(\'sk%d\');return false;">-%s</a>
               <br />
               <div class="smaller">
               &nbsp;&nbsp;<b>File:</b> %s<br />
               &nbsp;&nbsp;<b>Agent:</b> %s<br />
               &nbsp;&nbsp;<b>Modification time:</b>
               %s<br />
               </div>

               </div>
            """ % (sk_count, ffile_name, sk_count, ffile_name, ffile_name, syscheck['_name'], dt2)

            pass

        buffer += "</td></tr></table>"
        buffer += "<br /> <br />\n"

        #syscheck_count = 0
        #syscheck_list2 = []
        ## {'time_stamp':time_stamp, '_name':_name, 'sk_file_name':sk_file_name}
        #for syscheck in syscheck_list['global_list']['files']:
        #    ts = datetime.datetime.fromtimestamp(int(syscheck['time_stamp'])).strftime("%m/%d/%Y %H:%M:%S")
        #    syscheck_list2.append({'id':syscheck_count, 'ts':ts, 'name':syscheck['_name'], 'filename':syscheck['sk_file_name']})
        #    syscheck_count += 1
        #pass

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
