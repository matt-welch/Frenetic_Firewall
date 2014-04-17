"""
Team 5 - Ben Boren, Erin Lanus, Matt Welch
simple_firewall.py reimplements the firewall-like functionality in the 
previous Firewall.py POX module. This is a reimplementation in Pyretic .
"""

from pox.lib.addresses import *

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
import pox.lib.packet as pkt

class firewall(DynamicPolicy):

    def __init__(self):
        #Initialize the firewall
        print "initializing firewall"
        self.firewall = {}
        super(firewall,self).__init__(true)
		# 0.0.0.0/0 is the wildcard for the ANY IP address match
        self.AddRule('10.0.0.1',5555,'10.0.0.2',555)
        self.update_policy()
    def AddRule(self, ip1, port1, ip2, port2):
        self.firewall[(ip1, port1, ip2, port2)] = True
        print "Adding Firewall rule in %s:%s -  %s:%s" % (ip1 , port1 , ip2 , port2)

    def update_policy(self):
        # select allowed traffic
		#
		#
		#if(ip1=='any'): ip1='0.0.0.0/0'

        protomatch = match(protocol=pkt.ipv4.TCP_PROTOCOL ) & match(dstport=port2) &
            match(ethtype=pkt.ethernet.IP_TYPE)
        for (ip1, port1, ip2, port2) in self.firewall.keys() 
            # new policy is initially a basic policy matching only on protocols
            newpolicy = protomatch

            # build a new policy
            if(ip1 != 'any'):
                newpolicy = newpolicy & match(srcip=ip1)
            if(srcport != 'any'):
                newpolicy = newpolicy & match(srcport=port1)
            if(ip2 != 'any'):
                newpolicy = newpolicy & match(dstip=ip2)
            if(dstport != 'any'):
                newpolicy = newpolicy & match(dstport=port2)
    
            # join with the old policy
            self.policy = union([ newpolicy & policy ])
        print self.policy

def main(configuration=""):
    # read config file
    # for everline in config file
    # call AddRule(dstip, dstport, srcport, srcport)
    return firewall() >> fwd(2)
    # was flood()
