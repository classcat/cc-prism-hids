
##############################################################
# ClassCat(R) Prism for HIDS
#  Copyright (C) 2015 ClassCat Co.,Ltd. All rights reseerved.
##############################################################


from collections import OrderedDict

import os.path

#
# Set the handle directory and create the ossec handler.
#
def os_handle_start(dir):
    ossec_handle = OrderedDict()
    #ossec_handle['dir'] = None
    #ossec_handle['agent_dir'] = None
    #ossec_handle['name'] = None
    #ossec_handle['error'] = None

    # 20 minutes
    #ossec_handle['notify_time'] = 1200;

    if os.path.exists(dir):
        ossec_handle['dir'] = dir
        #ossec_handle['agent_dir'] = dir + "/queue/agent-info"

        return ossec_handle

    return None
