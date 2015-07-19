

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

    FOOTER = """\
<!-- OSSEC UI footer -->

<div id="footer">
    <p class="center">All Content &copy; 2006 - 2013 <a href="http://www.trendmicro.com"><font color="red"><b>Trend Micro</b></font></a>. All rights reserved</p>
</div>

<!-- END of FOOTER -->
"""

    def __init__(self):
        print("I'm view view")
    pass
