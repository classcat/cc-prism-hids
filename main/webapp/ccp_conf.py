
##############################################################
# ClassCat(R) Prism for HIDS
#  Copyright (C) 2015 ClassCat Co.,Ltd. All rights reseerved.
##############################################################

# ===  Notice ===
# all python scripts were written by masao (@classcat.com)
#
# === History ===
# 02-aug-15 : fixed for beta.
#

import os.path

ccp_conf = {
    'lang' : 'ja',

    'username' : 'cc-admin',

    'password' : 'ClassCat',

    # Ossec directory
    'ossec_dir' : "/var/ossec",

    # Maximum alerts per page
    'ossec_max_alerts_per_page' : 1000,

    # Default search values
    'ossec_search_level' : 7,

    'ossec_search_time' : 14400,

    'ossec_refresh_time' : 90
}


class CCPConf (object):
    def __init__(self):
        self.lang = ccp_conf['lang']

        self.username = ccp_conf['username']
        self.password = ccp_conf['password']

        self.ossec_dir = ccp_conf['ossec_dir']
        self.ossec_max_alerts_per_page = ccp_conf['ossec_max_alerts_per_page']
        self.ossec_search_level = ccp_conf['ossec_search_level' ]
        self.ossec_search_time = ccp_conf['ossec_search_time']
        self.ossec_refresh_time = ccp_conf['ossec_refresh_time']

    def check_dir(self):
        if os.path.exists(self.ossec_dir):
            return True
        else:
            return False
