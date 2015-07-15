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

@app.route("/main")
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
    print(syscheck_list)

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

    print ("syscheck_list2")
    print(syscheck_list2)

    alert_list = os_lib_alerts.os_getalerts(ossec_handle, 0, 0, 30)

    now = datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")
    return render_template("main.html", now=now, agent_list=agent_list2,
                                                syscheck_global_list = syscheck_list2)

@app.route("/test")
def hello():
    return u"Hello World! testテスト"

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
