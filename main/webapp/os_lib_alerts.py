#/usr/bin/env python
# -*- coding: utf-8 -*-

"""
/* Copyright (C) 2006-2008 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */
"""

##############################################################
# ClassCat(R) Prism for HIDS
#  Copyright (C) 2015 ClassCat Co.,Ltd. All rights reseerved.
##############################################################

# === Notice ===
# all python scripts were written by masao (@classcat.com)
#
# === History ===

import os
from datetime import *
import time
import os.path
import re
import gzip
import glob

from collections import OrderedDict

from mydebug import MYDEBUG

from Ossec.Alert import Ossec_Alert
from Ossec.AlertList import Ossec_AlertList

gcounter_alerts = 0

# TODO: This can probably be a method of AlertList
def __os_createresults(out_file, alert_list):
    # Opening output file
    myhome  = os.environ['CCPRISM_HOME']

    mytmpdir = myhome + "/tmp"
    if not os.path.exists(mytmpdir):
        os.mkdir (mytmpdir)

    out_file = myhome + out_file

    fobj = open(out_file, "w")
    fobj.write(alert_list.toHtml())
    fobj.close()

"""

 * @param string $location_pattern
 *   String used for constraining results by location. This will be used in a
 *   call to strpos, and may contain an initial '!' signifying negation. If
 *   present, the '!' will be stripped and not used in the call to strpos, but
 *   the results of the call will be negated.


  * @param string $log_pattern
 *   String used for constraining results by log group. This will be used in a
 *   call to strpos.

 * @param string $log_regex
 *   String used for constraining results by log group. This will be used in a
 *   call to preg_match.

 * @param array $rc_code_hash
 *   Array keyed on pattern variable name. Contains 'true' if pattern should be
 *   negated, false otherwise. Valid keys are 'srcip_pattern', 'str_pattern'
 *   'user_pattern' and 'location_pattern'.

 * @return Ossec_Alert
"""

def __os_parsealert(fobj, curr_time,
                        init_time, final_time, min_level ,
                        rule_id,
                        location_pattern,
                        str_pattern,
                        group_pattern, group_regex,
                        srcip_pattern, user_pattern,
                        log_pattern, log_regex,
                        rc_code_hash):

    if False:
        print(">> IN __os_parsealert")
        args = """\n
fobj : %s
curr_time : %s
init_time : %s
final_time : %s
min_level : %s
rule_id : %s
location_pattern : %s
str_pattern : %s
group_pattern : %s
group_regex : %s
srcip_pattern : %s
user_pattern : %s
log_pattern : %s
log_regex : %s
rc_code_hash : %s
""" % (fobj, curr_time, init_time, final_time, min_level, rule_id, location_pattern, str_pattern,
            group_pattern, group_regex, srcip_pattern, user_pattern, log_pattern, log_regex, rc_code_hash
            )
        print(args)
        """
        obj : <gzip _io.BufferedReader name='/var/ossec/logs/alerts/2015/Jul/ossec-alerts-23.log.gz' 0x7f704626b198>
        curr_time : 1437719168
        init_time : 1437604680
        final_time : 1437705480
        min_level : 3
        rule_id : /111/
        location_pattern : loc_pattern
        str_pattern : pattern_abc
        group_pattern : web_scan (None)
        group_regex : None (/connection_attempt|web_scan|recon/)
        srcip_pattern : 192.168.0.50
        user_pattern : root
        log_pattern : sshd
        log_regex : None
        rc_code_hash : OrderedDict([('user_pattern', False), ('str_pattern', False), ('srcip_pattern', False), ('location_pattern', False)])

        """

    evt_time = 0
    evt_id = 0
    evt_level = 0
    evt_description = None
    evt_location = None
    evt_srcip = None
    evt_user = None
    evt_group = None
    evt_msg = []
    evt_msg.append("")
    # php : evt_msg[0] = ""

    while True:
        buffer = fobj.readline()
        if not buffer:
            break

        # since binary open
        buffer = buffer.decode('UTF-8')

        # Getting event header
        if not buffer.startswith("** Alert"):
            continue
        #mobj = re.search("^\*\*\sAlert.+", buffer)
        #if not mobj:
        #    continue

        global gcounter_alerts
        gcounter_alerts += 1

        # Getting event time
        evt_time = buffer[9:19]
        if evt_time.isdigit():
            evt_time = int(evt_time)
        else:
            evt_time = 0
            continue

        # Checking if event time is in the timeframe
        if (init_time != 0) and (evt_time < init_time):
            continue

        if (final_time !=  0) and (evt_time > final_time):
            return None

        pos = buffer.find("-")
        if pos == -1:
            # Invalid Group
            continue
        else:
            evt_group = buffer[pos:]

        #  buffer : ** Alert 1437663586.8449575: - pam,syslog,authentication_success,
        # evt_group : - pam,syslog,authentication_success,

        # Filtering baesd on the group
        if group_pattern is not None:
            if evt_group.find (group_pattern) == -1:
                continue
        elif group_regex is not None:
            if not re.search(group_regex.strip("/"), evt_group):
                continue

        # Getting log formats
        if log_pattern is not None:
            if evt_group.find(log_pattern) == -1:
                continue
        elif log_regex is not None:
            if not re.search(log_regex.strip("/"), evt_group):
                continue

        # Getting location
        # 2015 Jul 23 23:59:46 mikoto->/var/log/auth.log
        buffer = fobj.readline()
        buffer = buffer.decode('UTF-8')

        evt_location = buffer[21:]

        if location_pattern:
            if evt_location.find(location_pattern) == -1:
                if not rc_code_hash['location_pattern']:
                    continue
            else:
                if rc_code_hash['location_pattern']:
                    continue

        # Getting rule, level and descriptioni
        # Rule: 5502 (level 3) -> 'Login session closed.'
        buffer = fobj.readline()
        buffer = buffer.decode('UTF-8')

        # Rule: 5501 (level 3) -> 'Login session opened.'
        # tokens[0] Rule:
        # tokesn[1] 5501
        # tokens[2] (level
        # tokens[3] 3)
        # tokens[4] ->
        # tokens[5] 'Login session opened.'

        tokens = buffer.split(" ")
        if len(tokens) == 1:
            continue

        # Rule id
        evt_id = tokens[1]
        if not evt_id.isdigit():
            continue

        # Checking rule id
        if rule_id is not None:
            if not re.search(rule_id.strip("/"), evt_id):
                continue

        # Level
        evt_level = tokens[3].rstrip(')')

        if not evt_level.isdigit():
            continue

        evt_level = int(evt_level)
        min_level = int(min_level)

        # Checking event level
        if evt_level < min_level:
            continue

        # Getting description
        tokens2 = buffer.split("->")
        evt_description = tokens2[1].strip().strip("''")

        # Starting OSSEC 2.6, "Src IP:" and "User:" are optional in alerts.log.

        # srcip
        buffer = fobj.readline()
        buffer = buffer.decode('UTF-8')

        if buffer[0:7] == "Src IP:":
            # run srcip code
            buffer = buffer.strip()
            evt_srcip = buffer[8:]

            mobj = re.match('^(\d|[01]?\d\d|2[0-4]\d|25[0-5])\.(\d|[01]?\d\d|2[0-4]\d|25[0-5])\.(\d|[01]?\d\d|2[0-4]\d|25[0-5])\.(\d|[01]?\d\d|2[0-4]\d|25[0-5])$', evt_srcip)
            # if(preg_match("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}^", $evt_srcip))
            if mobj:
                # valid IP
                pass
            else:
                evt_srcip = '(none)'

            if srcip_pattern is not None:
                if evt_srcip.find(srcip_pattern) == -1:
                    if not rc_code_hash['srcip_pattern']:
                        continue
                else:
                    if rc_code_hash['srcip_pattern']:
                        continue

            # read line to buffer
            buffer = fobj.readline()
            buffer = buffer.decode('UTF-8')

        if buffer[0:5] == "User:":
            # run user code
            buffer = buffer.strip()
            if buffer != "User: (none)":
                evt_user = buffer[6:]
                if evt_user == "SYSTEM":
                    evt_user = None

            if user_pattern:
                if (evt_user is None) or (evt_user.find(user_pattern) == -1):
                    if not rc_code_hash['user_pattern']:
                        continue
                else:
                    if rc_code_hash['user_pattern']:
                        continue
                pass

            buffer = fobj.readline()
            buffer = buffer.decode('UTF-8')

        # move on to message

        # message
        # 宣言済み
        #    evt_msg = []
        #    evt_msg.append("")

        msg_id = 0
        #evt_msg = []
        #evt_msg.append(None)
        evt_msg[msg_id] = None

        # masao added :
        pattern_matched = 0

        while(len(buffer)>3):
            if buffer == "\n":
                break

            if (str_pattern is not None) and (buffer.find(str_pattern) > -1):
                pattern_matched = 1

            #buffer = buffer.decode('UTF-8')
            evt_msg[msg_id] = buffer.strip().replace('<', "&lt;").replace('>', "&gt;")

            buffer = fobj.readline()
            buffer = buffer.decode('UTF-8')

            msg_id += 1
            evt_msg.append(None)

        # Searcing by pattern
        if rc_code_hash is not None:
            if (str_pattern is not None) and (pattern_matched == 0) and (rc_code_hash['str_pattern']):
                evt_srcip = None
                evt_user = None
                continue
            elif (not rc_code_hash['str_pattern']) and (pattern_matched == 1):
                evt_srcip = None
                evt_user = None
                continue

        # if we reach here, we got a full alert.

        alert = Ossec_Alert()

        alert.time = evt_time
        alert.id = evt_id
        alert.level = evt_level

        #  // TODO: Why is this being done here? Can't we just use
        # // htmlspecialchars() before emitting this to the browser?
        if evt_user:
            evt_user = evt_user.replace('<', "&lt;").replace('>', "&gt;")
        alert.user = evt_user

        if evt_srcip:
            evt_srcip = evt_srcip.replace('<', "&lt;").replace('>', "&gt;")
        alert.srcip = evt_srcip

        alert.description = evt_description
        alert.location = evt_location
        alert.msg = list(evt_msg)  # 配列の代入はあり？

        #print (line)
        #print(alert.dump())

        return alert

    return None



def os_searchalerts(ossec_handle,
                        search_id,
                         init_time,   final_time,
                         max_count = 1000,  min_level = 7,   rule_id = None,
                         location_pattern = None,  str_pattern = None,  group_pattern = None,
                         srcip_pattern = None,   user_pattern = None,  log_pattern = None)  :

    """
     *  @param integer $min_level
     *  Used to constrain events by level. Events with levels lower than this value
     *  will not be returned. Passed directly to __os_parsealert.
    """

    if False:
        print (">> IN os_searchalerts in os_lib_alerts.py\n")

        fmt_init_time  = datetime.fromtimestamp(init_time)
        fmt_final_time = datetime.fromtimestamp(final_time)
        in_args = """\
init_time : %s
final_time : %s
max_count : %s
min_level : %s
rule_id : %s
location_pattern %s
str_pattern : %s
group_pattern : %s
srcip_pattern : %s
user_pattern : %s
log_pattern : %s
""" % (fmt_init_time, fmt_final_time, max_count, min_level, rule_id, location_pattern,
            str_pattern, group_pattern, srcip_pattern, user_pattern, log_pattern)

        print (in_args)

        """
        init_time : 2015-07-23 07:38:00
        final_time : 2015-07-24 11:38:00
        max_count : 5000
        min_level : 3
        rule_id : 111
        location_pattern loc_pattern
        str_pattern : pattern_abc
        group_pattern : web_scan
        srcip_pattern : 192.168.0.50
        user_pattern : root
        log_pattern : sshd
        """

    alert_list = Ossec_AlertList()

    file_count = 0
    file_list = []
    #file_list[0] = ""
    #     $file_list[0] = array();

    """
output_file[0]
array(1) { ["count"]=> int(1000) }
output_file[1]
string(60) "./tmp/output-tmp.1-1000-f95606de5c49b31df3348c8001ae0ab4.php"

output_file[0]
array(2) { ["count"]=> int(2000) [1]=> int(999) }
output_file[2]
string(60) "./tmp/output-tmp.2-1000-f95606de5c49b31df3348c8001ae0ab4.php"

output_file[0]
array(3) { ["count"]=> int(3000) [1]=> int(999) [2]=> int(999) }
output_file[3]
string(60) "./tmp/output-tmp.3-1000-f95606de5c49b31df3348c8001ae0ab4.php"

output_file[0]
array(4) { ["count"]=> int(4000) [1]=> int(999) [2]=> int(999) [3]=> int(999) }
output_file[4]
string(60) "./tmp/output-tmp.4-1000-f95606de5c49b31df3348c8001ae0ab4.php"
    """

    output_count = 1
    output_file = []
    output_file.append(OrderedDict())
    output_file.append(None)
    #output_file.append(None)
    #output_file.append(OrderedDict())
    #output_file[0] = ""
    #output_file[1] = ""

    curr_time = int(time.time())

    # added by masao
    rc_code_hash = OrderedDict()

    # Clearing arguments
    if rule_id is not None:
        rule_id = "/%s/" % rule_id

    group_regex = None
    if (group_pattern is not None) and (group_pattern.find("|") != -1):
        group_regex = "/%s/" % group_pattern
        group_pattern = None

    log_regex = None
    if (log_pattern is not None) and (log_pattern.find("|") != -1):
        log_regex = "/%s/" % log_pattern
        log_pattern = None

    # Setting rc code
    if (user_pattern is not None) and user_pattern and (user_pattern[0] == '!'):
        user_pattern = user_pattern[1:]
        rc_code_hash['user_pattern'] = True
    else:
        rc_code_hash['user_pattern'] = False

    # str
    if (str_pattern is not None) and str_pattern and (str_pattern[0] == '!'):
        str_pattern = str_pattern[1:]
        rc_code_hash['str_pattern'] = True #  TODO : True?
        # rc_code_hash['str_pattern'] = False #  TODO : True?
    else:
        rc_code_hash['str_pattern'] = False
        # rc_code_hash['str_pattern'] = True

    # srcip
    if (srcip_pattern is not None) and srcip_pattern and (srcip_pattern[0] == '!'):
        srcip_pattern = srcip_pattern[1:]
        rc_code_hash['srcip_pattern'] = True
    else:
        rc_code_hash['srcip_pattern'] = False

    # location
    if (location_pattern is not None) and location_pattern and (location_pattern[0] == '!'):
        location_pattern = location_pattern[1:]
        rc_code_hash['location_pattern'] = True
    else:
        rc_code_hash['location_pattern'] = False

    # Cleaning old entries
    os_cleanstored(None)

    global gcounter_alerts
    gcounter_alerts = 0

    # Getting first file
    init_loop = init_time
    while init_loop <= final_time:
        l_year_month = datetime.fromtimestamp(init_loop).strftime("%Y/%b") # 2015/Jul
        l_day = datetime.fromtimestamp(init_loop).strftime("%d")

        file_list.append("logs/alerts/%s/ossec-alerts-%s.log" % (l_year_month, l_day))
        #file_list.appned(None)
        #file_list[file_count] = "logs/alerts/%s/ossec-alerts-%s.log" % (l_year_month, l_day)

        # Adding one day
        init_loop+=86400
        file_count += 1

    # Getting each file
    for file in file_list:
        #print ("Let's check a file %s" % file)
        # If the file does not exist, it must be gzipped so switch to a
        # compressed stream for reading and try again. If that also fails,
        # abort this log file and continue on to the next one.
        log_file = ossec_handle.ossec_dir + "/" + file
#                log_file = ossec_handle['dir'] + "/" + file


        fobj = None
        try:
            fobj = open(log_file, "rb")
        except Exception as e:
            try:
                fobj = gzip.open(log_file + ".gz", "rb")
            except Exception as e:
                continue

        # Reading all the entries
        while True:
            # Dont get more than max count alerts per page
            if alert_list.size() >= max_count:
                # output_file[1]
                # string(60) "./tmp/output-tmp.1-1000-f95606de5c49b31df3348c8001ae0ab4.php"
                #  in python : ./tmp/output-tmp.1-1000-917f3b294dd1a044411b45813c06b58d.php

                output_file[output_count] = "/tmp/output-tmp.%03d-%s-%s.py" % (output_count, alert_list.size(), search_id)
                #output_file[output_count] = "/tmp/output-tmp.%s-%s-%s.py" % (output_count, alert_list.size(), search_id)

                __os_createresults(output_file[output_count], alert_list)

                output_file[0][output_count] = alert_list.size()-1
                alert_list = Ossec_AlertList()
                output_count += 1
                output_file.append(None)

            alert = __os_parsealert(fobj, curr_time, init_time,
                                     final_time, min_level,
                                     rule_id, location_pattern,
                                     str_pattern, group_pattern,
                                     group_regex,
                                     srcip_pattern, user_pattern,
                                     log_pattern, log_regex,
                                     rc_code_hash);

            # final time を超えると、None が返される
            if alert is None:
                print("Let's break")
                break

            if not 'count' in output_file[0]:
                output_file[0]['count'] = 0

            output_file[0]['count'] += 1

            # Adding alert
            alert_list.addAlert(alert)

        # Closing file
        if fobj:
            #print("goint to close %s" % fobj)
            fobj.close()

    #print("gcounter_alerts is %s" % gcounter_alerts)

    # Creating last entry
    output_file[output_count] = "/tmp/output-tmp.%03d-%s-%s.py" % (output_count, alert_list.size(), search_id)
    #output_file[output_count] = "/tmp/output-tmp.%s-%s-%s.py" % (output_count, alert_list.size(), search_id)

    # output_file.append("./tmp/output-tmp.%s-%s-%s.php" % (output_count, alert_list.size(), search_id))

    output_file[0][output_count] = alert_list.size() - 1
    output_file.append(None)

    __os_createresults(output_file[output_count], alert_list)

    output_file[0]['pg'] = output_count

    #print(output_file)

    return output_file


"""
 * Clean out stored search result files. If a search ID is given, all result
 * files for that search ID will be unlinked. If the given search ID is NULL,
 * all temporary files older than 30 minutes will be deleted.
 *
 * @param String $search_id
 *   A randomly-generated unique search ID or NULL.
 """
def  os_cleanstored(search_id = None):

    #if (MYDEBUG):
    #    print(">> IN os_cleanstored")
    #    print(os.environ["CCPRISM_HOME"])

    if search_id is not None:
        pass

    else:
        for file in glob.glob(os.environ["CCPRISM_HOME"] + "/tmp/*.py"):
            if int(os.stat(file).st_mtime) < (int(time.time()) - 1800):
                os.unlink(file)


    pass


def os_getstoredalerts(ossec_handle, search_id):

    output_file = []
    output_file.append(OrderedDict())
    output_file[0]['count'] = 0
    output_file.append(None)

    output_count = 1

    # Cleaining old entries
    os_cleanstored(None)

    filepattern = "\/tmp\/output-tmp\.(\d{1,3})-(\d{1,6})-[a-z0-9]+\.py$"

    target_files = "%s/tmp/output-tmp.*-*-%s.py" % (os.environ['CCPRISM_HOME'], search_id)

    for filename in sorted(glob.glob(target_files)):
        str_page_n = ""
        page_n = 0
        alert_count = 0

        regs = re.search(filepattern, filename)
        if regs:
            str_page_n = regs.group(1)
            page_n = int(regs.group(1))
            alert_count = int(regs.group(2))
        else:
            continue

        if (page_n >= 1) and (page_n < 512):
            output_file[page_n] = "/tmp/output-tmp.%s-%s-%s.py" % (str_page_n, alert_count, search_id)
            #  output_file[page_n] = filename
            output_file[0][page_n] = alert_count

            #output_file[page_n+1] = None
            output_file.append(None)
            output_file[0]['count'] += alert_count

            output_count += 1

    output_file[0]['pg'] = output_count - 1

    #print(output_file)

    return output_file


def os_getalerts(ossec_handle, init_time = 0, final_time = 0, max_count = 30):
    # TODO: This is always called with init_time=0, final_time=0 and max_count=30.

    file = ""
    alert_list = Ossec_AlertList()
    curr_time = datetime.now()

    log_file = ossec_handle.ossec_dir + "/logs/alerts/alerts.log"
    #    log_file = ossec_handle['dir'] + "/logs/alerts/alerts.log"

    fobj = None
    try:
        fobj = open(log_file, 'rb')
    except Exception as e:
        raise Exception("file binary open failed. (os_getalerts#os_lib_alerts) %s" % e)
    #fobj = open(log_file, 'r')

    #   If times are set to zero, we monitor the last *count files. */
    if init_time == 0  and final_time == 0:
        # clearstatcache()
        # os_cleanstored()

        # Getting file size
        info = os.stat(log_file)
        f_size = info.st_size

        # Average size of every event: 300-350
        f_point = max_count * 325

        #  If file size is large than the counter fseek to the average place in the file.

        if f_size > f_point:
            seek_place = f_size - f_point
            fobj.seek(seek_place, 0)
            # １行だけ捨てても無意味なので注意
            #tmpbuf_to_discard = fobj.readline()
            #print(tmpbuf_to_discard)
        pass

        while True:
            alert = __os_parsealert(fobj, curr_time, init_time, final_time, 0, None, None,
                                                        None, None, None, None, None, None, None, None)
            #);

            #if alert:
            #    alert.dump()

            if alert is None:
                break

            alert_list.addAlert(alert)
            pass

    fobj.close()
    return alert_list
    pass


### End of Script ###
