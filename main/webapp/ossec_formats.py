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
# 30-jul-15 : fixed for beta
#

from collections import OrderedDict


log_categories = OrderedDict([
    ("Syslog", OrderedDict([
        ("Syslog (all)", "syslog"),
        ("Sshd", "sshd"),
        ("Arpwatch", "arpwatch"),
        ("Ftpd", "ftpd"),
        ("Pam Unix", "pam"),
        ("Proftpd", "proftpd"),
        ("Pure-ftpd", "pure-ftpd"),
        ("Vsftpd", "vsftpd"),
        ("Sendmail", "sendmail"),
        ("Postfix", "postfix"),
        ("Imapd", "imapd"),
        ("Vpopmail", "vpopmail"),
        ("Spamd", "spamd"),
        ("Horde IMP", "horde"),
        ("Smbd", "smbd"),
        ("NFS", "nfs"),
        ("Xinetd", "xinetd"),
        ("Kernel", "kernel"),
        ("Su", "su"),
        ("Cron", "cron"),
        ("Sudo", "sudo"),
        ("PPTP", "pptp"),
        ("Named", "named")
        ] )
	),

	("Firewall", OrderedDict([
        ("Firewall", "firewall|pix"),
        ("Pix", "pix"),
        ("Netscreen", "netscreenfw")
        ] )
	),

	("Microsoft", OrderedDict([
        ("Microsoft (all)", "windows|msftp|exchange"),
        ("Windows", "windows"),
        ("MS Ftp", "msftp"),
        ("Exchange", "exchange")
        ] )
	),

	("Web logs", OrderedDict([
        ("Web logs (all)", "web-log")
        ] )
	),

	("Squid", OrderedDict([
        ("Squid (all)", "squid")
        ])
	),

	("Security devices", OrderedDict([
        ("Security devices (all)", "symantec|cisco_vpn|ids"),
        ("Cisco VPN", "Cisco VPN"),
        ("Symantec AV", "symantec"),
        ("NIDS", "ids")
        ])
	)

]
)

### End of Script ###
