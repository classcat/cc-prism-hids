#!/usr/bin/env python
# -*- coding: utf-8 -*-

##############################################################
# ClassCat(R) Prism for HIDS
#  Copyright (C) 2015 ClassCat Co.,Ltd. All rights reseerved.
##############################################################


"""
>>> import sys
>>> import locale
>>> sys.stdout.encoding
'UTF-8'
>>> sys.getdefaultencoding()
'ascii'
>>> locale.getpreferredencoding()
'UTF-8'

"""

import os,sys
import locale

from flask import Flask, session, request, redirect, render_template, url_for
from flask import jsonify, make_response

from ccp_conf import CCPConf

app = Flask(__name__)
app.config['SECRET_KEY'] = 'The secret key which cipers the cookie'


###########
### Root ###
###########

@app.route("/")
def root():
    return redirect("/main")


###########
### Main ###
###########

@app.route("/main", methods = ['GET'])
def main():
    from ccprism.main import Main

    ccmain = Main(request, CCPConf())
    return ccmain.getHtml()


###############
### SysCheck ###
###############

@app.route("/syscheck", methods = ['GET', 'POST'])
def syscheck():
    from ccprism.syscheck import SysCheck

    ccsyscheck = SysCheck(request, CCPConf())
    return ccsyscheck.getHtml()


############
### Search ###
############

@app.route("/search", methods = ['GET', 'POST'])
def search():
    from ccprism.search import Search

    ccsearch = Search(request, CCPConf())
    return ccsearch.getHtml()


###########
### Stats ###
###########

@app.route("/stats", methods = ['GET', 'POST'])
def stats():
    from ccprism.stats import Stats

    ccstats = Stats(request, CCPConf())
    return ccstats.getHtml()


############
### About ###
############

@app.route("/help", methods= ['GET'])
def help():
    from ccprism.help import Help

    cchelp = Help(request, CCPConf())
    return cchelp.getHtml()


###

@app.context_processor
def example():
    return dict(myexample='This is an example')

#{{ format_price(0.33) }}

#{{myexample}}

@app.context_processor
def utility_processor():
    def format_price(amount, currency=u'€'):
        return u'{0:.2f}{1}'.format(amount, currency)
    return dict(format_price=format_price)


if __name__ == "__main__":
    ccprism_home = os.environ['CCPRISM_HOME']
    sys.path.insert(0, ccprism_home + "/main/pylib")

    #print(locale.getlocale())
    #locale.setlocale(locale.LC_ALL, "")
    #print(locale.getlocale())
    #locale.setlocale(locale.LC_ALL, "")

    print("main scritpt : " + os.getcwd())

    app.run(host="0.0.0.0", debug=True)
