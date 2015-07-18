#/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re

def __os_getdb(file, _name):
    print (file)
    print(_name)

    fobj = open(file, 'r')
    while True:
        line = fobj.readline()
        if not line:
            break
    fobj.close()


    buffer = "がうがう"

    return (None, buffer)


def __os_getchanges(file, g_last_changes, _name):

    if not 'files' in g_last_changes:
        g_last_changes['files'] = []

    change_list = []
    #change_list_dict = {}
    #change_list_tpl = []
    list_size = 0

    info = os.stat(file)
    size = info.st_size

    seek_offset = max(size -12000, 0)
    f = open(file, 'r')
    f.seek(seek_offset, 0)

    # Cleaning up first entry
    buffer = f.readline()

    #counter = 0

    #regx = ''/^(\+|#)/"
    regex_pattern_to_skip = "^(\+|#)"
    regex_obj = re.compile(regex_pattern_to_skip)

    regex_pattern2 = "^!(\d+)\s(.+)$"
    #regx2 = "/^\!(\d+) (.+)$/"
    regex_obj2 = re.compile(regex_pattern2)

    while (1):
        line = f.readline()
        mobj = regex_obj.match(line)
        if mobj:
            continue

        #counter += 1
        if not line:
            break

        # !++4061272:33261:0:0:bedd153d0761ba18ddeb041ef558691d:40725e5ec9c6609e5fbe620ac9765a7ea7167b22 !1436708545 /usr/bin/python3.4m
        # :33261:0:0:bedd153d0761ba18ddeb041ef558691d:40725e5ec9c6609e5fbe620ac9765a7ea7167b22 !1436708545 /usr/bin/python3.4m
        # !1436708545 /usr/bin/python3.4m

        pos_col = line.index(':')
        line2 = line[pos_col:]
        pos_ex = line2.index('!')
        new_buffer = line2[pos_ex:]

        mobj2 = regex_obj2.match(new_buffer)
        if mobj2:
            list_size += 1

            time_stamp = mobj2.group(1)
            sk_file_name = mobj2.group(2)

            if list_size < 20:
                #change_list[sk_file_name] = time_stamp
                change_list.append({'sk_file_name':sk_file_name, 'time_stamp':time_stamp})

            else:
                print (change_list)
                change_list = sorted(change_list, key=lambda x:x['time_stamp'], reverse=True)
                change_list.pop ()
                change_list.append({'sk_file_name':sk_file_name, 'time_stamp':time_stamp})

                # 最終的に昇順か降順で揃えなくて良い？
                # というか、使われてない？

            # global list
            if len(g_last_changes['files']) < 100:
                g_last_changes['files'].append({'time_stamp':time_stamp, '_name':_name, 'sk_file_name':sk_file_name})

                if not 'lowest' in g_last_changes:
                    g_last_changes['lowest'] = time_stamp
                else:
                    if time_stamp < g_last_changes['lowest'] :
                        g_last_changes['lowest'] = time_stamp

                g_last_changes['files'] = sorted(g_last_changes['files'], key=lambda x:x['time_stamp'], reverse=True)

            elif time_stamp > g_last_changes['lowest']:
                g_last_changes['files'] = sorted(g_last_changes['files'], key=lambda x:x['time_stamp'], reverse=True)
                g_last_changes['files'].pop()
                g_last_changes['files'].append({'time_stamp':time_stamp, '_name':_name, 'sk_file_name':sk_file_name})

                pass

    f.close()
    pass

# Dump syscheck db
def os_syscheck_dumpdb(ossec_handle, agent_name):
    #$dh = NULL;
    file = "";
    syscheck_list = []
    syscheck_count = 0

    sk_dir = ossec_handle['dir'] + "/queue/syscheck"

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

        print("MATCH ! MATCH !!!!!!!!!!")
        (syscheck_list, buffer2) = __os_getdb(sk_dir + "/" + file, _name)
        buffer += buffer2

        # syscheck_list will not be used ...

    #buffer = "nyaochan"
    return buffer
    pass

def os_getsyscheck(ossec_handle = None):
    syscheck_list = {}
    syscheck_count = 0

    sk_dir = ossec_handle['dir'] + "/queue/syscheck"

    # .syscheck.cpt
    # syscheck

    g_last_changes = {}

    filelist = os.listdir(sk_dir)
    for file in filelist:
        _name = ""
        if file[0] == '.':
            continue

        if file == "syscheck":
            _name = "ossec-server"
        else:
            continue

        syscheck_list[_name] = {}
        syscheck_list[_name]['list'] =  __os_getchanges(sk_dir + "/" + file, g_last_changes, _name);


        syscheck_count += 1

    else:
        syscheck_list['global_list'] = g_last_changes
        print("----------------------------")
        for key in syscheck_list:
            print (key)
        print("-----------------------------")
        return(syscheck_list);

    return None
    pass
