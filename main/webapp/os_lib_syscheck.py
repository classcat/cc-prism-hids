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

#

import os, sys
import datetime
import re
import traceback

from collections import OrderedDict

def __os_getdb(file, _name):
    db_list = OrderedDict()
    mod_list = OrderedDict()
    db_count = 0
    set_size = 1

    fobj = open(file, 'r')

    # Database pattern
    skpattern = "^\S\S\S(\d+):(\d+):(\d+:\d+):(\S+):(\S+) \!(\d+) (.+)$"

    while True:
        line = fobj.readline()
        if not line:
            break

        line = line.strip()

        # Sanitizing input
        line = line.replace('<', "&lt;")
        line = line.replace('>', "&gt;")

        mobj = re.search(skpattern, line)
        if mobj:
            sk_file_size =  mobj.group(1)
            sk_file_perm  = mobj.group(2)
            sk_file_owner = mobj.group(3)
            sk_file_md5   = mobj.group(4)
            sk_file_sha1  = mobj.group(5)
            time_stamp   = mobj.group(6)
            sk_file_name = mobj.group(7)

            #print(sk_file_name)

            if sk_file_name in db_list:
                mod_list[time_stamp] = {0:db_count, 1:sk_file_name}
                #mod_list.append({'time_stamp':{0:db_count, 1:sk_file_name}})

                db_list[sk_file_name]['ct'] = db_count
                db_list[sk_file_name]['time'] = time_stamp

                db_list[sk_file_name]['size'] =  "%s<br />&nbsp;&nbsp; -> &nbsp;&nbsp;<br /> %s" % (db_list[sk_file_name]['size'], sk_file_size)

                db_list[sk_file_name]['sum'] = "%s<br />&nbsp;&nbsp; -> &nbsp;&nbsp;<br /> md5 %s <br />sha1 %s" % (db_list[sk_file_name]['sum'], sk_file_md5, sk_file_sha1)

            else:
                #print("heyhneyhey")
                db_list[sk_file_name] = {}
                db_list[sk_file_name]['time'] = time_stamp
                db_list[sk_file_name]['size'] = sk_file_size
                db_list[sk_file_name]['sum'] = "md5 %s<br /> sha1 %s" % (sk_file_md5, sk_file_sha1)
                pass

            db_count += 1

    fobj.close()

    # Prinitng latest files
    buffer = ""

    buffer += "         <br /><br />"
    buffer += "     <h2>Latest modified files:</h2><br />"

    #   mod_list['time_stamp'] = {0:db_count, 1:sk_file_name}
    mod_list_keys = mod_list.keys()
    mod_list_keys_sorted = sorted(mod_list_keys, reverse=True)
    for ts in mod_list_keys_sorted:
        record = mod_list[ts]

        ts2 = datetime.datetime.fromtimestamp(int(ts)).strftime("%m/%d/%Y %H:%M")

        buffer += "<b>%s&nbsp;&nbsp;</b>" % ts2
        buffer += """ <a class="bluez" href="#id_%s">%s</a><br/>""" % (record[0], record[1])
        #print (mod_list[ts])



    #for key in mod_list_keys:
    #    print (key)
    #print(mod_list_keys)

    buffer += "\n<br /><h2>Integrity Checking database: %s</h2>\n" % _name

    # Printing db
    buffer += '<br /><br /><table width="100%">'
    buffer += """        <tr>
           <th>File name</th>
           <th>Checksum</th>"""

    if set_size == 1:
        buffer += "<th>Size</th>"

    buffer += "</tr>"

    # Dumping for each entry
    db_count = 0
    for list_name, list_val in db_list.items():
        #print(list_name)
        sk_class = ">"
        sk_point = ""

        if (db_count % 2) == 0:
            sk_class = 'class="odd">'

        if "ct" in list_val:
            sk_point = """<a id="id_%s" />""" % list_val['ct']

        buffer += """\
            <tr %s<td width="45%%" valign="top">%s%s</td>
            <td width="53%%" valign="top">%s</td>
        """ % (sk_class, sk_point, list_name, list_val['sum'])
        #buffer += """\
        #<tr %s<td width="45\%" valign="top">%s%s</td><td width="53\%" valign="top">%s</td>""" % (sk_class, #sk_point, list_name, list_val['sum'])

        if set_size == 1:
            buffer += """<td width="2%%" valign="top">%s</td>""" % (list_val['size'])
            pass

        buffer += "</tr>"

        db_count += 1

    buffer += "</table>"

    return (db_list, buffer)


def __os_getchanges(file, g_last_changes, _name):
    #@ 29-jul-15 : fixed for beta.

    if not 'files' in g_last_changes:
        g_last_changes['files'] = []

    change_list = []  # TODO : is the even used ? このリストを実際には返さない。
    #change_list_dict = {}
    #change_list_tpl = []
    change_list2 = OrderedDict()
    list_size = 0

    size = 0
    try:
        info = os.stat(file)
        size = info.st_size
    except Exception as e:
        #traceback.print_exc(file=sys.stdout)
        raise Exception("os.stat failed (__os_getchanges#os_lib_syscheck) : %s" % e)

    fobj = None
    seek_offset = max(size -12000, 0)

    try:
        fobj = open(file, 'r')
    except Exception as e:
        #traceback.print_exc(file=sys.stdout)
        raise Exception ("file open failed. (__os_getchanges#os_lib_syscheck) : %s" % e)

    fobj.seek(seek_offset, 0)

    # Cleaning up first entry (seek したので)
    buffer = fobj.readline()

    #regx = ''/^(\+|#)/"
    regex_pattern_to_skip = "^(\+|#)"  # 最初の文字が + か #  ならスキップ
    regex_obj = re.compile(regex_pattern_to_skip)

    regex_pattern2 = "^!(\d+)\s(.+)$"
    #regx2 = "/^\!(\d+) (.+)$/"
    regex_obj2 = re.compile(regex_pattern2)

    while True:
        buffer = fobj.readline()

        if not buffer:
            break

        buffer = buffer.strip()

        mobj = regex_obj.match(buffer)
        if mobj:
            continue

        # !++4061272:33261:0:0:bedd153d0761ba18ddeb041ef558691d:40725e5ec9c6609e5fbe620ac9765a7ea7167b22 !1436708545 /usr/bin/python3.4m
        # :33261:0:0:bedd153d0761ba18ddeb041ef558691d:40725e5ec9c6609e5fbe620ac9765a7ea7167b22 !1436708545 /usr/bin/python3.4m
        # !1436708545 /usr/bin/python3.4m

        pos_col = buffer.index(':')
        buffer2 = buffer[pos_col:]
        pos_ex = buffer2.index('!')
        new_buffer = buffer2[pos_ex:]

        mobj2 = regex_obj2.match(new_buffer) # "^!(\d+)\s(.+)$"
        if mobj2:
            list_size += 1

            time_stamp = mobj2.group(1)
            sk_file_name = mobj2.group(2)

            # If the list is small
            if list_size < 20:
                #change_list[sk_file_name] = time_stamp
                change_list.append({'sk_file_name':sk_file_name, 'time_stamp':time_stamp})

                change_list2[sk_file_name] = time_stamp

            else:
                change_list = sorted(change_list, key=lambda x:x['time_stamp'], reverse=True)
                change_list.pop ()
                change_list.append({'sk_file_name':sk_file_name, 'time_stamp':time_stamp})

                change_list2 = OrderedDict(sorted(change_list2.items(), key=lambda x: x[1], reverse=True))
                change_list2.popitem()
                change_list2[sk_file_name] = time_stamp

                # 最終的に昇順か降順で揃えなくて良い？
                # というか、使われてない？

            # global list
            if len(g_last_changes['files']) < 100:
                g_last_changes['files'].append({'time_stamp':time_stamp, '_name':_name, 'sk_file_name':sk_file_name})

                if not 'lowest' in g_last_changes.keys():
                    g_last_changes['lowest'] = time_stamp

                if time_stamp < g_last_changes['lowest'] :
                    g_last_changes['lowest'] = time_stamp

                g_last_changes['files'] = sorted(g_last_changes['files'], key=lambda x:x['time_stamp'], reverse=True)

            elif time_stamp > g_last_changes['lowest']:
                g_last_changes['files'] = sorted(g_last_changes['files'], key=lambda x:x['time_stamp'], reverse=True)
                g_last_changes['files'].pop()
                g_last_changes['files'].append({'time_stamp':time_stamp, '_name':_name, 'sk_file_name':sk_file_name})

    if fobj:
        fobj.close()


# Dump syscheck db
def os_syscheck_dumpdb(ossec_handle, agent_name):
    #$dh = NULL;
    file = "";
    syscheck_list = []
    syscheck_count = 0

    sk_dir = ossec_handle.ossec_dir + "/queue/syscheck"
    #     sk_dir = ossec_handle['dir'] + "/queue/syscheck"


    buffer = ""

    # Getting all agent files
    filelist = os.listdir(sk_dir)
    for file in filelist:
        _name = ""
        if file[0] == '.':
            continue

        if file == "syscheck":
            _name = "ossec-server"
        else:
            continue

        # Looing for agent name
        if _name != agent_name:
            continue

        (syscheck_list, buffer2) = __os_getdb(sk_dir + "/" + file, _name)
        buffer += buffer2

        # syscheck_list will not be used ...

    #buffer = "nyaochan"
    return buffer
    pass


def os_getsyscheck(conf):
    #@ 29-jul-15 : fixed for beta.
    syscheck_list = OrderedDict()
    syscheck_count = 0

    sk_dir = "%s%s" % (conf.ossec_dir, "/queue/syscheck")

    # .syscheck.cpt
    # syscheck

    g_last_changes = OrderedDict()
    #     g_last_changes = {}

    filelist = os.listdir(sk_dir)

    filepattern = "^\(([\.a-zA-Z0-9_-]+)\) " + "([0-9\._]+|any)->([a-zA-Z_-]+)$"

    for file in filelist:
        _name = ""

        if file[0] == '.':
            continue

        regs = re.match(filepattern, file)
        if regs:
            if regs.group(2) == "syscheck-registry":
                _name = regs.group(1) + " Windows registry"
            else:
                _name = regs.group(1)
        else:
            if file == "syscheck":
                _name = "ossec-server"
            else:
                continue

        syscheck_list[_name] = OrderedDict()
        # 実際には何も返ってこない。
        syscheck_list[_name]['list'] =  __os_getchanges(sk_dir + "/" + file, g_last_changes, _name);

        syscheck_count += 1

    syscheck_list['global_list'] = g_last_changes

    # filelist が [] の場合は、{'global_list' : {} } を返すことになる。
    return(syscheck_list);


### End of Script ###
