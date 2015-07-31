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

import os
from datetime import *
import time
import os.path
import re
import gzip
import glob

from collections import OrderedDict

#from mydebug import MYDEBUG

from Ossec.Alert import Ossec_Alert
from Ossec.AlertList import Ossec_AlertList

def __os_parsestats(fobj, month_hash):
    print (fobj)
    print (month_hash)

    daily_hash = OrderedDict()

    # Initializing daily hash
    daily_hash['total'] = 0
    daily_hash['alerts'] = 0
    daily_hash['syscheck'] = 0
    daily_hash['firewall'] = 0

    # Regexes
    global_regex = "^(\\d+)--(\\d+)--(\\d+)--(\\d+)--(\\d+)$";
    rules_regex = "^(\\d+)-(\\d+)-(\\d+)-(\\d+)$";

    while True:
        buffer = fobj.readline()

        if not buffer:
            break

        buffer = buffer.strip()

        # Getting total number of events/alerts
        regs = re.match(global_regex, buffer)
        if regs:
            # 6--1343--1725--0--0
            if not 'alerts_by_hour' in daily_hash:
                daily_hash['alerts_by_hour'] = OrderedDict()
            daily_hash['alerts_by_hour'][regs.group(1)] = regs.group(2)

            if not 'total_by_hour' in daily_hash:
                daily_hash['total_by_hour'] =  OrderedDict()
            daily_hash['total_by_hour'][regs.group(1)] = regs.group(3)

            if not 'syscheck_by_hour' in daily_hash:
                daily_hash['syscheck_by_hour'] =  OrderedDict()
            daily_hash['syscheck_by_hour'][regs.group(1)] = regs.group(4)

            if not 'firewall_by_hour' in daily_hash:
                daily_hash['firewall_by_hour'] =  OrderedDict()
            daily_hash['firewall_by_hour'][regs.group(1)] = regs.group(5)

            daily_hash['alerts'] += int(regs.group(2))
            daily_hash['total'] += int(regs.group(3))
            daily_hash['syscheck'] += int(regs.group(4))
            daily_hash['firewall'] += int(regs.group(5))

        else:
            # 6-5501-3-350
            regs = re.match(rules_regex, buffer)
            if regs:
                # By level
                if not 'level' in daily_hash:
                    daily_hash['level'] = OrderedDict()
                if not regs.group(3) in daily_hash['level']:
                    daily_hash['level'][regs.group(3)] = 0
                daily_hash['level'][regs.group(3)] += int(regs.group(4))

                if not 'level' in month_hash:
                    month_hash['level'] = OrderedDict()
                if not regs.group(3) in month_hash['level']:
                    month_hash['level'][regs.group(3)] = 0
                month_hash['level'][regs.group(3)] += int(regs.group(4))

                # By rule
                if not 'rule' in daily_hash:
                    daily_hash['rule'] = OrderedDict()
                if not regs.group(2) in daily_hash['rule']:
                    daily_hash['rule'][regs.group(2)] = 0
                daily_hash['rule'][regs.group(2)] += int(regs.group(4))

                if not 'rule' in month_hash:
                    month_hash['rule'] = OrderedDict()
                if not regs.group(2) in month_hash['rule']:
                    month_hash['rule'][regs.group(2)]  = 0
                month_hash['rule'][regs.group(2)] += int(regs.group(4))

            else:
                continue

    # Filling month hash
    month_hash['total'] += daily_hash['total']
    month_hash['alerts'] += daily_hash['alerts']
    month_hash['firewall'] += daily_hash['firewall']
    month_hash['syscheck'] += daily_hash['syscheck']

    #print ("-vvvvvvvvvvvvvvvvv")
    #print(month_hash['total'])

    return (daily_hash)


def os_getstats(conf, init_time, final_time):
    # 01-aug-15 : fixed for beta
    stats_list = OrderedDict()
    stats_count = 1

    file_list = []
    file_list.append(None)
    #file_list[0] = None
    file_count = 0

    curr_time = int(time.time())

    # Initializing month hash
    month_hash = OrderedDict()
    month_hash['total']  = 0
    month_hash['alerts'] = 0
    month_hash['firewall'] = 0
    month_hash['syscheck'] = 0

    # Getting first file
    init_loop = init_time
    while init_loop <= final_time:

        l_year_month = datetime.fromtimestamp(init_loop).strftime("%Y/%b")
        l_day = datetime.fromtimestamp(init_loop).strftime("%d")  # 0 padding

        # ここでは、0 でのパディングが必要
        # ex) stats/totals/2015/Jul/ossec-totals-04.log
        file = "stats/totals/%s/ossec-totals-%s.log" % (l_year_month, l_day)

        l_day = str(int(l_day))  # これ、重要、padding をはずして、文字列に

        log_file = conf.ossec_dir + "/" + file

        # Adding one day
        init_loop += 86400
        file_count += 1

        # Opening alert file
        if os.path.exists (log_file):
            fobj = None
            try:
                fobj = open(log_file, 'r')
            except Exception as e:
                continue

            stats_hash = __os_parsestats(fobj, month_hash)

            if stats_hash['total'] != 0:
                if not l_year_month in stats_list.keys():
                    stats_list[l_year_month] = OrderedDict()
                stats_list[l_year_month][l_day] = stats_hash

            if fobj:
                fobj.close()

    # Monthly hash goes to day 0
    if not l_year_month in stats_list.keys():
        stats_list[l_year_month] = OrderedDict()
    stats_list[l_year_month]["0"] = month_hash

    return (stats_list)


### End of Script ###
