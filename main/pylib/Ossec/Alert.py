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
# ClassCat(R) Prism for HIDS
#  Copyright (C) 2015 ClassCat Co.,Ltd. All rights reseerved.
##############################################################

# ===  Notice ===
# all python scripts were written by masao (@classcat.com)
#
# === TODO ===
# 30-jul-15 : Search ID の website 上の検索
#
# === History ===
# 30-jul-15 : fixed for beta
#

from datetime import *

class Ossec_Alert(object):
    def __init__(self):
        self.time = 0
        self.id = 0
        self.level = 0
        self.user = ""
        self.srcip = ""
        self.description = ""
        self.location = ""
        self.msg = []


    def dump(self):
        print ("\n### Ossec_Alert ###")
        print (self.time)
        print(self.id)
        print(self.level)
        print(self.user)
        print(self.srcip)
        print(self.description)
        print(self.location)
        print(self.msg)
        print ("#####################\n")


    def toHtml(self, lang):
        is_lang_ja = False
        if lang == "ja":
            is_lang_ja = True

        date = datetime.fromtimestamp(int(self.time)).strftime("%H:%M:%S %m/%d/%Y")

        id_link = "<a href=\"http://www.ossec.net/doc/search.html?q=rule-id-%s\">%s</a>" % (self.id, self.id)

        message = ""
        if len(self.msg) > 1:
            if self.msg[-1] is None:
                self.msg.pop()
            message = "<br/>".join(self.msg)

        srcip = "";
        if (self.srcip is not None) and (self.srcip != '(none)') and (self.srcip != ""):
            if is_lang_ja:
                srcip = "<div class=\"alertindent\">ソース IP: </div>%s<br/>" % (self.srcip)
            else:
                srcip = "<div class=\"alertindent\">Src IP: </div>%s<br/>" % (self.srcip)

        user = ""
        if (self.user is not None) and (self.user != ""):
            if is_lang_ja:
                user = "<div class=\"alertindent\">ユーザ: </div>%s<br/>" % self.user
            else:
                user = "<div class=\"alertindent\">User: </div>%s<br/>" % self.user

        myclass = "level_%s id_%s srcip_%s" % (self.level, self.id, self.srcip)

        if is_lang_ja:
            html = """\
            <div class="alert %s">
            <span class="alertdate">%s</span>
            <div class="alertindent">レベル: </div><div class="alertlevel">%d - <span class="alertdescription">%s</span></div>
            <div class="alertindent">ルール Id: </div>%s <br />
            <div class="alertindent">ログ位置: </div>%s<br />
            %s
            %s
            <div class="msg">%s</div>
            </div>
            """ % (myclass, date, self.level, self.description, id_link, self.location, srcip, user, message)

        else:
            html = """\
            <div class="alert %s">
            <span class="alertdate">%s</span>
            <div class="alertindent">Level: </div><div class="alertlevel">%d - <span class="alertdescription">%s</span></div>
            <div class="alertindent">Rule Id: </div>%s <br />
            <div class="alertindent">Location: </div>%s<br />
            %s
            %s
            <div class="msg">%s</div>
            </div>
            """ % (myclass, date, self.level, self.description, id_link, self.location, srcip, user, message)

        return html

### End of Script ###
