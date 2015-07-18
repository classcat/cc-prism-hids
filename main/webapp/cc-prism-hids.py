#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os,sys

from flask import Flask, session, request, redirect, render_template, url_for
from flask import jsonify, make_response

app = Flask(__name__)
app.config['SECRET_KEY'] = 'The secret key which cipers the cookie'

@app.route("/")
def root():
    return redirect("/main")

@app.route("/main", methods=['GET'])
def main():
    import os_lib_handle
    import os_lib_agent
    import os_lib_syscheck
    import os_lib_alerts
    import ossec_conf
    import datetime
    ossec_handle = os_lib_handle.os_handle_start(ossec_conf.ossec_dir)
    if ossec_handle is None:
        print("Unable to access ossec directory.\n")
        return(1)

    agent_list = os_lib_agent.os_getagents(ossec_handle)
    agent_list2 = []
    agent_count = 0

    for agent in agent_list:
        agent['id'] = agent_count
        agent_count += 1

        agent['change_time_fmt'] = datetime.datetime.fromtimestamp(agent['change_time']).strftime("%m/%d/%Y %H:%M:%S")

        atitle = ""
        aclass = ""
        amsg = ""

        #If agent is connected
        if agent['connected']:
            atitle = "Agent active"
            aclass = "bluez"
        else:
            atitle = "Agent Inactive"
            aclass = "red"
            amsg = " - Inactive"

        agent['atitle'] = atitle
        agent['aclass'] = aclass
        agent['amsg'] = amsg

        agent_list2.append(agent)

    syscheck_list = os_lib_syscheck.os_getsyscheck(ossec_handle)

    syscheck_count = 0
    syscheck_list2 = []
    # {'time_stamp':time_stamp, '_name':_name, 'sk_file_name':sk_file_name}
    for syscheck in syscheck_list['global_list']['files']:
        ts = datetime.datetime.fromtimestamp(int(syscheck['time_stamp'])).strftime("%m/%d/%Y %H:%M:%S")
        syscheck_list2.append({'id':syscheck_count, 'ts':ts, 'name':syscheck['_name'], 'filename':syscheck['sk_file_name']})
        syscheck_count += 1
        if syscheck_count >= 10:
            break
        pass

    alert_list = os_lib_alerts.os_getalerts(ossec_handle, 0, 0, 30)

    alert_count = alert_list.size() - 1
    alert_array  = alert_list.alerts()

    alert_list_html = ""
    while (alert_count>=0):
        alert_list_html += alert_array[alert_count].toHtml()
        alert_count -= 1

    now = datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")
    return render_template("main.html", now=now, agent_list=agent_list2,
                                                syscheck_global_list = syscheck_list2,
                                                alert_list_html=alert_list_html)


@app.route("/syscheck", methods = ['GET', 'POST'])
def syscheck():
    from ccprism.syscheck import SysCheck

    ccsyscheck = SysCheck(request)
    return ccsyscheck.getHtml()

@app.route("/xxsyscheck", methods = ['GET', 'POST'])
def xxsyscheck():
    import datetime
    import ossec_conf
    import os_lib_handle
    import os_lib_syscheck
    if request.method == 'POST':
        pass

    ossec_handle = os_lib_handle.os_handle_start(ossec_conf.ossec_dir)

    syscheck_list = os_lib_syscheck.os_getsyscheck(ossec_handle)

    syscheck_count = 0
    syscheck_list2 = []
    # {'time_stamp':time_stamp, '_name':_name, 'sk_file_name':sk_file_name}
    for syscheck in syscheck_list['global_list']['files']:
        ts = datetime.datetime.fromtimestamp(int(syscheck['time_stamp'])).strftime("%m/%d/%Y %H:%M:%S")
        syscheck_list2.append({'id':syscheck_count, 'ts':ts, 'name':syscheck['_name'], 'filename':syscheck['sk_file_name']})
        syscheck_count += 1
        #if syscheck_count >= 10:
        #    break
        pass

    html = """\
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html xmlns="http://www.w3.org/1999/xhtml">
    	<head>
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
        </head>
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

    return html
    #return render_template("syscheck.html", syscheck_global_list = syscheck_list2)
    pass

@app.route("/xsyscheck", methods = ['GET', 'POST'])
def xsyscheck():
    import datetime
    import ossec_conf
    import os_lib_handle
    import os_lib_syscheck
    if request.method == 'POST':
        pass

    ossec_handle = os_lib_handle.os_handle_start(ossec_conf.ossec_dir)

    syscheck_list = os_lib_syscheck.os_getsyscheck(ossec_handle)

    syscheck_count = 0
    syscheck_list2 = []
    # {'time_stamp':time_stamp, '_name':_name, 'sk_file_name':sk_file_name}
    for syscheck in syscheck_list['global_list']['files']:
        ts = datetime.datetime.fromtimestamp(int(syscheck['time_stamp'])).strftime("%m/%d/%Y %H:%M:%S")
        syscheck_list2.append({'id':syscheck_count, 'ts':ts, 'name':syscheck['_name'], 'filename':syscheck['sk_file_name']})
        syscheck_count += 1
        #if syscheck_count >= 10:
        #    break
        pass


    return render_template("syscheck.html", syscheck_global_list = syscheck_list2)
    pass


@app.context_processor
def example():
    return dict(myexample='This is an example')

#{{ format_price(0.33) }}

#{{myexample}}

@app.context_processor
def utility_processor():
    def format_price(amount, currency=u'€'):
        return u'{0:.2f}{1}'.format(amount, currency)
    return dict(format_price=format_price)

if __name__ == "__main__":
    ccprism_home = os.environ['CCPRISM_HOME']
    sys.path.insert(0, ccprism_home + "/main/pylib")

    app.run(host="0.0.0.0", debug=True)
