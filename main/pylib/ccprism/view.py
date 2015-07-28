

class View(object):

    HEAD = """\
    <title>OSSEC Web Interface - Open Source Security</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <link rel="shortcut icon" href="static/css/images/favicon.ico" />
    <link rel="stylesheet" type="text/css" media="all"  href="static/css/cal.css" title="css/cal.css" />
    <script type="text/javascript" src="static/js/calendar.js"></script>
    <script type="text/javascript" src="static/js/calendar-en.js"></script>
    <script type="text/javascript" src="static/js/calendar-setup.js"></script>
    <script type="text/javascript" src="static/js/prototype.js"></script>
    <script type="text/javascript" src="static/js/hide.js"></script>
    <link rel="stylesheet" rev="stylesheet"   href="static/css/css.css" type="text/css" />
"""

    HEAD_JA = """\
    <title>ClassCat&reg; Prism for HIDS (derived from OSSEC Web Interface)</title>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <link rel="shortcut icon" href="static/css/images/favicon.ico" />
    <link rel="stylesheet" type="text/css" media="all"  href="static/css/cal.css" title="css/cal.css" />
    <script type="text/javascript" src="static/js/calendar.js"></script>
    <script type="text/javascript" src="static/js/calendar-en.js"></script>
    <script type="text/javascript" src="static/js/calendar-setup.js"></script>
    <script type="text/javascript" src="static/js/prototype.js"></script>
    <script type="text/javascript" src="static/js/hide.js"></script>
    <link rel="stylesheet" rev="stylesheet"   href="static/css/css.css" type="text/css" />
"""

    HEADER = """\
<!-- OSSEC UI header -->

<div id="header">
  <div id="headertitle">
      <table>
      <tr>
        <td>
          &nbsp;&nbsp;<a href="http://www.ossec.net/">
          <img width="191" height="67" src="static/img/ossec_webui.png" title="Go to OSSEC.net" alt="Go to OSSEC.net"/></a>
        </td>

        <td>
          <img width="107" height="38" src="static/img/webui.png"/><br>&nbsp;&nbsp; <i>Version 0.8</i>
        </td>
      </tr>
      </table>
  </div>

  <ul id="nav">
  <li><a href="main" title="Main">Main</a></li>
  <li><a href="search" title="Search events">Search</a></li>
  <li><a href="syscheck" title="Integrity checking">Integrity checking</a></li>
  <li><a href="stats" title="Stats">Stats</a></li>
  <li><a href="help" title="Help">About</a></li>
  </ul>
</div>

<!-- END OF HEADER -->
"""

    HEADER_JA = """\
<!-- OSSEC UI header -->

<div id="header">
  <div id="headertitle">
    <table style="background:orange;" width="100%" cellspacing=0 cellpadding=0>
    <tr>
        <td><div style="color:royalblue;font-size:24pt;font-weight:bold;font-family:'Times New Roman'">&nbsp;&nbsp;ClassCat&reg; Prism <span style="font-style:italic;">for HIDS</span></div>
        <td width="405px"><img src="static/ccimg/cc_logo_with_softlayer.png"/>
    </tr>
    </table>
  </div>

  <ul id="nav">
  <li><a href="main" title="Main">メイン</a></li>
  <li><a href="search" title="Search events">検索</a></li>
  <li><a href="syscheck" title="Integrity checking">整合性チェック</a></li>
  <li><a href="stats" title="Stats">統計情報</a></li>
  <li><a href="help" title="Help">About</a></li>
  </ul>
</div>

<!-- END OF HEADER -->
"""

    FOOTER = """\
<!-- OSSEC UI footer -->

<div id="footer">
    <p class="center">All Content &copy; 2006 - 2013 <a href="http://www.trendmicro.com"><font color="red"><b>Trend Micro</b></font></a>. All rights reserved</p>
</div>

<!-- END of FOOTER -->
"""

    def __init__(self, request, conf):

        self.request = request
        self.conf = conf

        self.lang = conf['lang']
        if conf['lang'] == 'ja':
            self.is_lang_ja = True
        else:
            self.is_lang_ja = False

        self.html = ""
        self.contents=  ""

        self.is_post = False
        if request.method == 'POST':
            self.is_post = True

        self.form = request.form


    def _make_html(self):
        tmpl_head  = View.HEAD
        if self.is_lang_ja:
            tmpl_head = View.HEAD_JA

        tmpl_header = View.HEADER
        if self.is_lang_ja:
            tmpl_header = View.HEADER_JA

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
""" % (tmpl_head, tmpl_header, self.contents, View.FOOTER)
        pass
