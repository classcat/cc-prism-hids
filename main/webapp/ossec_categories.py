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

global_categories = OrderedDict([
    # Reconnaissance categories
    ("Reconnaissance", OrderedDict([
        ("Reconnaissance (all)", "connection_attempt|web_scan|recon"),
        ("Connection attempt", "connection_attempt"),
        ("Web scan", "web_scan"),
        ("Generic scan", "recon")
        ] )
    ),
    # Authentication control categories
	("Authentication Control", OrderedDict([
        ("Authentication Control (all)", "authentication|invalid_login|adduser|policy_changed|account_changed"),
	    ("Authentication Success", "authentication_success"),
	    ("Authentication Failure", "authentication_failed"),
	    ("Invalid login", "invalid_login"),
	    ("Multiple auth failures", "authentication_failures"),
	    ("User account modified", "adduser|account_changed"),
	    ("Policy changed", "policy_changed")
        ] )
	),

    #Attack
	("Attack/Misuse", OrderedDict([
		("Attack/Misuse (all)", "exploit_attempt|invalid_access|attack|spam|sql_injection|rootcheck"),
	    ("Worm", "automatic_attack"),
	    ("Virus", "virus"),
	    ("Automatic attack", "automatic_attack"),
	    ("Exploit pattern", "exploit_attempt"),
	    ("Invalid access", "invalid_access"),
	    ("Spam", "spam"),
	    ("Multiple Spams", "multiple_spam"),
	    ("SQL Injection", "sql_injection"),
	    ("Generic Attack", "attack"),
	    ("Rootkit detection", "rootcheck")
        ] )
	),

	# Access control
	("Access Control", OrderedDict([
		("Access Control (all)", "access|unknown_resource|drop|client"),
	    ("Access denied", "access_denied"),
	    ("Access allowed", "access_allowed"),
	    ("Invalid access", "unknown_resource"),
	    ("Firewall Drop", "firewall_drop"),
	    ("Multiple fw drops", "multiple_drops"),
	    ("Client mis-configuration", "client_misconfig"),
	    ("Client error", "client_error")
        ] )
	),

    # 	Network control
    ("Network Control", OrderedDict([
        ("Network Control (all)", "new_host|ip_spoof"),
        ("New host detected", "new_host"),
        ("Possible ARP spoof", "ip_spoof")
        ] )
	),

    # System monitor
    ("System Monitor", OrderedDict([
        ("System Monitor (all)", "service|system|logs|invalid_request|promisc|syscheck|config_changed"),
        ("Service start", "service_start"),
        ("Service in Risk", "service_availability"),
        ("System error", "system_error"),
        ("Shutdown", "system_shutdown"),
        ("Logs removed", "logs_cleared"),
        ("Invalid request", "invalid_request"),
        ("Promiscuous mode detected", "promisc"),
        ("Configuration changed", "config_changed"),
        ("Integrity Checking", "syscheck"),
        ("File modification", "syscheck")
        ] )
	),

    #/ Policy violation
    ("Policy Violation", OrderedDict([
        ("Policy Violation (all)", "login_"),
	   ("Login time violation", "login_time"),
	   ("Login day violation", "login_day")
        ] )
	)

]
)
