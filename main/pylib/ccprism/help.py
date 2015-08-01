
##############################################################
# ClassCat(R) Prism for HIDS
#  Copyright (C) 2015 ClassCat Co.,Ltd. All rights reseerved.
##############################################################

# ===  Notice ===
# all python scripts were written by masao (@classcat.com)
#
# === History ===
# 02-aug-15 : english text for classcat
# 01-aug-15 : fixed for beta
#

import os,sys
import re

from flask import Flask, session, request, redirect, render_template, url_for
from flask import jsonify, make_response


from .view import View

class Help(View):

    def __init__(self, request, conf):
        super().__init__(request, conf)

        self._make_contents()
        self._make_html()


    def _make_contents(self):
        req       = self.request
        is_post = self.is_post
        form     = req.form

        buffer_classcat = ""
        if self.is_lang_ja:
            buffer_classcat = """\
<br/>
<h3 class="my">ClassCat&reg; Prism for HIDS</h3>
Copyright &copy; 2015 ClassCat&reg; Co.,Ltd. All rigths reserved.<br/>
<br/>
本ソフトウェアは OSSEC WEB UI を GNU General Public License (version 3) に従って<br/>
(株)クラスキャットが全てのコードを書き直したソフトウェアです。
<br/><br/>
<!-- <hr/> -->
            """
        else:
            buffer_classcat = """\
<br/>
<h3 class="my">ClassCat&reg; Prism for HIDS</h3>
Copyright &copy; 2015 ClassCat&reg; Co.,Ltd. All rigths reserved.<br/>
<br/>
本ソフトウェアは OSSEC WEB UI を GNU General Public License (version 3) に従って<br/>
(株)クラスキャットが全てのコードを書き直したソフトウェアです。
<br/><br/>
<!-- <hr/> -->
        """

        buffer = """\
<h2>About</h2>
%s
<!-- <br />
<font size="2">
OSWUI is a an open source web interface for the <a href="http://www.ossec.net">OSSEC-HIDS</a> project. For details on
how to install, configure or use it, please take a look at <a href="http://www.ossec.net/wiki/index.php/OSSECWUI:Install">http://www.ossec.net/wiki/index.php/OSSECWUI:Install</a>. <br /><br />
If you have any problems or questions, please use one of the free support options
available at <a href="http://www.ossec.net/?page_id=21">http://www.ossec.net/?page_id=21</a>.
<br /><br />
For information regarding commercial support, please visit <a href="http://www.ossec.net/?page_id=21">http://www.ossec.net/?page_id=21</a>.
<br /><br /><br /> -->
<!-- <h3 class="my">Development team</h3>

<dd><strong>Daniel Cid</strong> - dcid ( at ) dcid.me</dd>
<dd><strong>Chris Abernethy</strong> - chris.abernethy (at) ossec.net</dd>
<dd><strong>Vic Hargrave</strong> - ossec ( at )  vichargrave.com</dd>
<br /><br /><br /> -->

<h3 class="my">License</h3>
<font size="2">
      Copyright &copy; 2006 - 2013 <a href="http://www.trendmicro.com">Trend Micro</a>.  All rights reserved.
<br /><br />

OSSEC WEB UI (ossec-wui) is a free software; you can redistribute it and/or modify it under the terms of the GNU General Public License (version 2) as published by the FSF - Free Software Foundation.
<br /><br />
OSSEC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
</font>


""" % buffer_classcat

        self.contents = buffer


#    def getHtml(self):
#        return self.html

### End of Script ###
