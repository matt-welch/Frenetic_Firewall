"""
Team 5 - Ben Boren, Erin Lanus, Matt Welch
Simple_Firewall.py reimplements the firewall-like functionality in the 
previous Firewall.py POX module. This is a reimplementation in Pyretic .
"""

from pox.lib.addressses import *

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner

class firewall(DynamicPolicy)

    def __init__(self)
        #Initialize the firewall
        print "initializing firewall"
        self.firewall = {}
        super(firewall,self).__init__(true)

    def AddRule(self, ip1, ip2, port1, port2):
        self.firewall[(ip1, ip2, port1, port2)] = true
        print "Adding Firewall rule in %s:%s -  %s:%s" % (ip1 , port1 , ip2 , port2)
	self.update_policy()

    def update_policy(self):
        
        #select traffic to flood?
        #self.policy = union([...
        #select traffic to filter?
	#self.filter(~union([...
        print self.policy

def main(configuration=""):
	return firewall >> flood()
