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
# 29-jul-15 : fixed for beta.
#

import time
import subprocess

def os_getagents(conf):
    agent_list = []
    agent_count = 0

    agent_list.append({})
    agent_list[agent_count]['change_time'] = time.time()
    agent_list[agent_count]['name'] = "ossec-server"
    agent_list[agent_count]['ip'] = "127.0.0.1"
    os = subprocess.check_output(["uname", "-a"])
    agent_list[agent_count]['os'] = os.strip().decode('utf-8')
    agent_list[agent_count]['connected'] = 1

    agent_count += 1

    return agent_list

### End of Script ###
