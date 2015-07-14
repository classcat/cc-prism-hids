#!/usr/bin/env python

import os.path

def os_handle_start(dir):
    ossec_handle = {}
    ossec_handle['dir'] = None
    ossec_handle['agent_dir'] = None
    ossec_handle['name'] = None
    ossec_handle['error'] = None

    if os.path.exists(dir):
        ossec_handle['dir'] = dir
        ossec_handle['agent_dir'] = dir + "/queue/agent-info"
        return ossec_handle

    return None
