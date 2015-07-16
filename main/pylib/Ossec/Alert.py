
import datetime

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

    def toHtml(self):

        date = datetime.datetime.fromtimestamp(int(self.time)).strftime("%H:%M:%S %m/%d/%Y")
        #   date = datetime.datetime.fromtimestamp(int(self.time)).strftime("%m/%d/%Y %H:%M:%S")

        id_link = "<a href=\"http://www.ossec.net/doc/search.html?q=rule-id-%s\">%s</a>" % (self.id, self.id)

        srcip = "";
        if (self.srcip != '(none)') and (self.srcip != ""):
            srcip = "<div class=\"alertindent\">Src IP: </div>%s<br/>" % (self.srcip)

        user = ""
        if self.user != "":
            user = "<div class=\"alertindent\">User: </div>%s<br/>" % self.user

        if self.msg[-1] is None:
            self.msg.pop()
        message = "<br/>".join(self.msg)

        myclass = "level_%s id_%s srcip_%s" % (self.level, self.id, self.srcip)

        html = """\
            <div class="alert %s$class">
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
        pass
    pass
