#!/usr/bin/env python

import time
import subprocess

def os_getagents(ossec_handle = None):
    agent_list = []
    agent_count = 0

    agent_list.append({})
    agent_list[agent_count]['change_time'] = time.time()
    agent_list[agent_count]['name'] = "ossec-server"
    agent_list[agent_count]['ip'] = "127.0.0.1"
    os = subprocess.check_output(["uname", "-a"])
    agent_list[agent_count]['os'] = os.strip().decode('utf-8')
    agent_list[agent_count]['connected'] = 1

    agent_count += agent_count

    # print (ossec_handle['agent_dir'])

    return agent_list
