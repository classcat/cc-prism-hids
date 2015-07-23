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

import os.path

#
# Set the handle directory and create the ossec handler.
#
def os_handle_start(dir):
    ossec_handle = OrderedDict()
    ossec_handle['dir'] = None
    ossec_handle['agent_dir'] = None
    ossec_handle['name'] = None
    ossec_handle['error'] = None

    # 20 minutes
    ossec_handle['notify_time'] = 1200;

    if os.path.exists(dir):
        ossec_handle['dir'] = dir
        ossec_handle['agent_dir'] = dir + "/queue/agent-info"

        return ossec_handle

    return None
