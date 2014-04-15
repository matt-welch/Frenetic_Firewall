"""
Team 5 - Ben Boren, Erin Lanus, Matt Welch
simple_firewall.py reimplements the firewall-like functionality in the 
previous Firewall.py POX module. This is a reimplementation in Pyretic .
"""

from pox.lib.addresses import *

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner

class firewall(DynamicPolicy):

    def __init__(self):
        #Initialize the firewall
        print "initializing firewall"
        self.firewall = {}
        super(firewall,self).__init__(true)
        self.AddRule('10.0.0.1',5555,'10.0.0.2',4444)

    def AddRule(self, ip1, port1, ip2, port2):
        self.firewall[(ip1, port1, ip2, port2)] = True
        print "Adding Firewall rule in %s:%s -  %s:%s" % (ip1 , port1 , ip2 , port2)
        self.update_policy()

    def update_policy(self):
        # select allowed traffic
        self.policy = union([ match(srcip=ip1) & match(dstip=ip2)
                for (ip1, port1, ip2, port2)
                in self.firewall.keys() ])
        print self.policy

def main(configuration=""):
    # read config file
    # for everline in config file
    # call AddRule(dstip, dstport, srcport, srcport)
    return firewall() >> flood()
