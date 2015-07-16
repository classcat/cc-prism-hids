
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
        pass
    pass
