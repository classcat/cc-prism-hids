"""
/**
 * Ossec Framework
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @category   Ossec
 * @package    Ossec
 * @version    $Id: Histogram.php,v 1.3 2008/03/03 15:12:18 dcid Exp $
 * @author     Chris Abernethy
 * @copyright  Copyright (c) 2007-2008, Daniel B. Cid <dcid@ossec.net>, All rights reserved.
 * @license    http://www.gnu.org/licenses/gpl-3.0.txt GNU Public License
 */
"""

##############################################################
#  Copyright C) 2015 Masashi Okumura All rights reseerved.
##############################################################


from collections import OrderedDict

"""
/**
 * This variable is an array keyed on category name, and each element is another
 * array keyed on sub-category name. The values of the subcategory arrays are
 * tags identifying event groups to be used to constrain search results. These
 * tags can be either plain strings or regular expressions to be used in a call
 * to preg_match (minus the enclosing '/' tokens).
 */
"""

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
