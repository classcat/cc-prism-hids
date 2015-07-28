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

import os,sys
import re

from flask import Flask, session, request, redirect, render_template, url_for
from flask import jsonify, make_response

from datetime import *
import time
import uuid
import hashlib

from collections import OrderedDict

from babel.numbers import format_decimal

import ossec_conf
import os_lib_handle
import os_lib_agent
import os_lib_alerts
import os_lib_stats
#import os_lib_syscheck

from ossec_categories import global_categories
from ossec_formats import log_categories

from .view import View

class Help(View):

    def __init__(self, request, conf):
        super().__init__(request, conf)

        #self.request = request




        self._make_contents()
        self._make_html()

    def _make_contents(self):
        req       = self.request
        is_post = self.is_post
        form     = req.form

        buffer = """\
<h2>About</h2>
<br />
<font size="2">
OSWUI is a an open source web interface for the <a href="http://www.ossec.net">OSSEC-HIDS</a> project. For details on
how to install, configure or use it, please take a look at <a href="http://www.ossec.net/wiki/index.php/OSSECWUI:Install">http://www.ossec.net/wiki/index.php/OSSECWUI:Install</a>. <br /><br />
If you have any problems or questions, please use one of the free support options
available at <a href="http://www.ossec.net/?page_id=21">http://www.ossec.net/?page_id=21</a>.
<br /><br />
For information regarding commercial support, please visit <a href="http://www.ossec.net/?page_id=21">http://www.ossec.net/?page_id=21</a>.
<br /><br /><br />
<h3 class="my">Development team</h3>

<dd><strong>Daniel Cid</strong> - dcid ( at ) dcid.me</dd>
<dd><strong>Chris Abernethy</strong> - chris.abernethy (at) ossec.net</dd>
<dd><strong>Vic Hargrave</strong> - ossec ( at )  vichargrave.com</dd>
<br /><br /><br />

<h3 class="my">License</h3>
<font size="2">
      Copyright &copy; 2006 - 2013 <a href="http://www.trendmicro.com">Trend Micro</a>.  All rights reserved.
<br /><br />

OSSEC WEB UI (ossec-wui) is a free software; you can redistribute it and/or modify it under the terms of the GNU General Public License (version 2) as published by the FSF - Free Software Foundation.
<br /><br />
OSSEC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
</font>


"""

        self.contents = buffer



    def _make_html(self):
        self.html = """\
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
%s
</head>

<body>
    <br/>
%s

<div id="container">
  <div id="content_box">
  <div id="content" class="pages">
  <a name="top"></a>

  <!-- BEGIN: content -->

  %s

  <!-- END: content -->

  <br /><br />
  <br /><br />
  </div>
  </div>

%s

</div>
</body>
</html>
""" % (View.HEAD, View.HEADER, self.contents, View.FOOTER)
        pass


    def getHtml(self):
        return self.html
