#!/usr/bin/env python

import os
import datetime
import os.path
import re

from Ossec.AlertList import Ossec_AlertList

def __os_parsealert(fobj, curr_time,
                        init_time, final_time, min_level ,
                        rule_id,
                        location_pattern,
                        str_pattern,
                        group_pattern, group_regex,
                        srcip_pattern, user_pattern,
                        log_pattern, log_regex,
                        rc_code_hash):
    while True:
        buffer = fobj.readline()
        if not buffer:
            break

        # ** Alert
        mobj = re.search("^\*\*\sAlert.+", buffer)
        if not mobj:
            continue

        print(buffer)
        # Getting event time
        evt_time = buffer[9:19]
        if not evt_time.isdigit():
            evt_time = 0
            continue

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
        evt_location = buffer[21:]
        print(buffer)
        print(evt_location)

        if location_pattern:
            pass

        # Getting rule, level and descriptioni
        # Rule: 5502 (level 3) -> 'Login session closed.'
        buffer = fobj.readline()
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

        # Checking event level
        if evt_level < min_level:
            continue

        # Getting description
        tokens2 = buffer.split("->")
        evt_description = tokens2[1].strip().strip("''")

        # Starting OSSEC 2.6, "Src IP:" and "User:" are optional in alerts.log.

        # srcip
        buffer = fobj.readline()
        print(buffer)
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
                print("OKKKKkkkkkkkkkkkkkkkkkkkkkkk")
                pass
            else:
                evt_srcip = '(none)'

            if srcip_pattern is not None:
                pass

            # read line to buffer
            buffer = fobj.readline()

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

        # move on to message

        # message
        print("Let's move on to msg")
        print(buffer)

        msg_id = 0
        evt_msg = []
        evt_msg.append(None)

        while(len(buffer)>3):
            if buffer == "\n":
                print("\\N found foun ############################")
                break

            if (str_pattern is not None): # and ():
                pass

            evt_msg[msg_id] = buffer.strip().replace('<', "&lt;").replace('>', "&gt;")

            buffer = fobj.readline()
            msg_id += 1
            evt_msg.append(None)

        # Searcing by pattern
        if (str_pattern is not None) and (pattern_matched == 0):
            pass

        # if we reach here, we got a full alert.
        print("vvv EVT_MSG vvv")
        print(evt_msg)

        #print (line)
        pass
    return None
    pass

def os_getalerts(ossec_handle, init_time = 0, final_time = 0, max_count = 30):
    file = ""
    alert_list = Ossec_AlertList()
    curr_time = datetime.datetime.now()

    print (ossec_handle['dir'])

    log_file = ossec_handle['dir'] + "/logs/alerts/alerts.log"

    fobj = open(log_file, 'r')

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

            if alert is None:
                break
            pass

    fobj.close()
    pass
