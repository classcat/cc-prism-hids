#!/usr/bin/env python

import os
from datetime import *
import time
import os.path
import re
import gzip

from collections import OrderedDict

from Ossec.Alert import Ossec_Alert
from Ossec.AlertList import Ossec_AlertList

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


def __os_parsealert(fobj, curr_time,
                        init_time, final_time, min_level ,
                        rule_id,
                        location_pattern,
                        str_pattern,
                        group_pattern, group_regex,
                        srcip_pattern, user_pattern,
                        log_pattern, log_regex,
                        rc_code_hash):

    evt_time = 0
    evt_id = 0
    evt_level = 0
    evt_description = ""
    evt_location = ""
    evt_srcip = ""
    evt_user = ""
    evt_group = ""
    #evt_msg = [""]
    #evt_msg.append("")

    while True:
        buffer = fobj.readline()
        if not buffer:
            break

        buffer = buffer.decode('UTF-8')

        # ** Alert
        mobj = re.search("^\*\*\sAlert.+", buffer)
        if not mobj:
            continue

        # Getting event time
        evt_time = buffer[9:19]
        if not evt_time.isdigit():
            evt_time = 0
            continue

        #print(">>>>" + evt_time)
        evt_time = int(evt_time)

        # Checking if event time is in the timeframe
        if (init_time != 0) and (evt_time < init_time):
            continue

        if (final_time !=  0) and (evt_time > final_time):
            return None

        pos = buffer.find("-")
        if pos < 0 :
            # Invalid Group
            continue
        #else:
        #    buffer[pos:]

        # Filtering baesd on the group
        if group_pattern is not None:
            pass
        elif group_regex is not None:
            pass

        # Getting log formats
        if log_pattern is not None:
            pass
        elif log_regex is not None:
            pass

        # Getting location
        buffer = fobj.readline()
        buffer = buffer.decode('UTF-8')
        evt_location = buffer[21:]

        if location_pattern:
            pass

        # Getting rule, level and descriptioni
        # Rule: 5502 (level 3) -> 'Login session closed.'
        buffer = fobj.readline()
        buffer = buffer.decode('UTF-8')
        print(buffer)
        tokens = buffer.split(" ")
        if len(tokens) == 1:
            continue

        print(tokens[0])
        print(tokens[1])

        # Rule id
        evt_id = tokens[1]
        if not evt_id.isdigit():
            continue

        # Checking rule id
        if rule_id is not None:
            pass

        # Level
        evt_level = tokens[3].rstrip(')')
        print("event : %s " %evt_level)
        print(evt_level)
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
            print("Match !!!!")
            # run srcip code
            buffer = buffer.strip()
            evt_srcip = buffer[8:]
            print(evt_srcip)

            mobj = re.match('^(\d|[01]?\d\d|2[0-4]\d|25[0-5])\.(\d|[01]?\d\d|2[0-4]\d|25[0-5])\.(\d|[01]?\d\d|2[0-4]\d|25[0-5])\.(\d|[01]?\d\d|2[0-4]\d|25[0-5])$', evt_srcip)
            # if(preg_match("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}^", $evt_srcip))
            if mobj:
                # valid IP
                pass
            else:
                evt_srcip = '(none)'

            if srcip_pattern is not None:
                pass

            # read line to buffer
            buffer = fobj.readline()
            buffer = buffer.decode('UTF-8')

        if buffer[0:5] == "User:":
            # run user code
            buffer = buffer.strip()
            print("User matched")
            if buffer != "User: (none)":
                evt_user = buffer[6:]
                if evt_user == "SYSTEM":
                    evt_user = None

            if user_pattern:
                pass

            print("EVT_UESR is")
            print(evt_user)

            buffer = fobj.readline()
            buffer = buffer.decode('UTF-8')

        # move on to message

        # message
        print("Let's move on to msg")
        print(buffer)

        msg_id = 0
        evt_msg = []
        evt_msg.append(None)

        print ("EVT_MSG BEFORE")
        print (evt_msg)
        while(len(buffer)>3):
            if buffer == "\n":
                print("\\N found foun ############################")
                break

            if (str_pattern is not None): # and ():
                pass

            #buffer = buffer.decode('UTF-8')
            evt_msg[msg_id] = buffer.strip().replace('<', "&lt;").replace('>', "&gt;")

            buffer = fobj.readline()
            buffer = buffer.decode('UTF-8')
            msg_id += 1
            evt_msg.append(None)

        # Searcing by pattern
        if (str_pattern is not None) and (pattern_matched == 0):
            pass

        # if we reach here, we got a full alert.

        alert = Ossec_Alert()
        #alert = Ossec.Alert.Ossec_Alert()
        alert.time = evt_time
        alert.id = evt_id
        alert.level = evt_level

        #  // TODO: Why is this being done here? Can't we just use
        # // htmlspecialchars() before emitting this to the browser?
        evt_user = evt_user.replace('<', "&lt;").replace('>', "&gt;")
        alert.user = evt_user

        evt_srcip = evt_srcip.replace('<', "&lt;").replace('>', "&gt;")
        alert.srcip = evt_srcip

        alert.description = evt_description
        alert.location = evt_location
        alert.msg = evt_msg  # 配列の代入はあり？

        #print (line)
        #print(alert.dump())

        return alert
        pass
    return None
    pass


def os_searchalerts(ossec_handle,
                        search_id,
                         init_time,
                         final_time,
                         max_count,
                         min_level,
                         rule_id,
                         location_pattern,
                         str_pattern,
                         group_pattern,
                         srcip_pattern,
                         user_pattern,
                         log_pattern)  :


    alert_list = Ossec_AlertList()

    file_count = 0
    file_list = []
    #file_list[0] = ""

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

    group_regex = None

    log_regex = None

    # Setting rc code
    rc_code_hash = None

    # srcip

    # location

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
        pass

    # Getting each file
    for file in file_list:
        #print (file)
        # If the file does not exist, it must be gzipped so switch to a
        # compressed stream for reading and try again. If that also fails,
        # abort this log file and continue on to the next one.
        log_file = ossec_handle['dir'] + "/" + file

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

                output_file[output_count] = "/tmp/output-tmp.%s-%s-%s.php" % (output_count, alert_list.size(), search_id)

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

            if alert is None:
                break

            if not 'count' in output_file[0]:
                output_file[0]['count'] = 0

            output_file[0]['count'] += 1

            # Adding alert
            alert_list.addAlert(alert)

        if fobj:
            fobj.close()

        # Creating last entry
        output_file[output_count] = "/tmp/output-tmp.%s-%s-%s.php" % (output_count, alert_list.size(), search_id)
        # output_file.append("./tmp/output-tmp.%s-%s-%s.php" % (output_count, alert_list.size(), search_id))

        output_file[0][output_count] = alert_list.size() - 1
        output_file.append(None)

        __os_createresults(output_file[output_count], alert_list)

        output_file[0]['pg'] = output_count

        return output_file



def os_getalerts(ossec_handle, init_time = 0, final_time = 0, max_count = 30):
    file = ""
    alert_list = Ossec_AlertList()
    curr_time = datetime.now()

    print (ossec_handle['dir'])

    log_file = ossec_handle['dir'] + "/logs/alerts/alerts.log"

    fobj = open(log_file, 'rb')
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
        print (f_size)
        print (f_point)

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

            if alert:
                alert.dump()

            if alert is None:
                break

            alert_list.addAlert(alert)
            pass

    fobj.close()
    return alert_list
    pass
