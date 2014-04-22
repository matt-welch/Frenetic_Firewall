"""
Team 5 - Ben Boren, Erin Lanus, Matt Welch
simple_firewall.py reimplements the firewall-like functionality in the 
previous Firewall.py POX module. This is a reimplementation in Pyretic.
"""

from pox.lib.addresses import *

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.mac_learner import mac_learner
import pox.lib.packet as pkt

OFPP_NORMAL = 0xfffa    # Process with normal L2/L3 switching.
class firewall(DynamicPolicy):
    def __init__(self):
        #Initialize the firewall
        print "initializing firewall"
        self.firewall = {}
        super(firewall,self).__init__(true)

        # push rules from the configuration file
        global config
        fin = open(config)
        for line in fin:
            rule = line.split()
            print rule
            if rule[1] != 'any':
                rule[1] = int(rule[1])
            if rule[3] != 'any':
                rule[3] = int(rule[3])
            if (len(rule) > 0) : # only make a rule if the line is not empty
                self.AddRule(rule[0], rule[1], rule[2], rule[3])
                print "Adding rule for: <",rule,">"
                #config.append(rule)
            if (False):
                print config   # for everline in config file
    
        # 0.0.0.0/0 is the wildcard for the ANY IP address match
        # can add rules hardcoded 
#        self.AddRule('10.0.0.5',5555,'any','any')
        print self.firewall
        self.update_policy()

        
    def AddRule(self, ip1, port1, ip2, port2):
        self.firewall[(ip1, port1, ip2, port2)] = True
        print "Adding Firewall rule in %s:%s -  %s:%s" % (ip1 , port1 , ip2 , port2)

    def clean_ip (cidrAddress):
        """
        Takes an address if the address is in CIDR notation and contains uintAddress
        hostAddress then the netmask portion is stripped from the address so that the
        address may be installed as an IP address in uintAddress flow
        (e.g. 192.168.1.4/24 becomes 192.168.1.4)
        """
        if PRINT_FUNCTION_NAMES:
            print "clean_ip()"
        strAddress = cidrAddress.split('/', 2)
        if len(strAddress) == 1:
            return cidrAddress
        uintAddress = IPAddr(strAddress[0]).toUnsigned()
        hostMask = 32-int(strAddress[1])
        hostAddress = uintAddress & ( (1<<hostMask) - 1 )
        if (hostAddress == 0):
            return cidrAddress
        else:
            return strAddress[0]
    
    def update_policy(self):
        # create a prototype rule specifying the ethertype and TCP
        protomatch = match(protocol=pkt.ipv4.TCP_PROTOCOL ) & match(ethtype=pkt.ethernet.IP_TYPE)
        # loop through the rules in the dictionary, unioning them with the existing policy
        for (ip1, port1, ip2, port2) in self.firewall.keys(): 
            # new policy is initially a basic policy matching only on protocols
            newpolicy = protomatch

            # build a new policy
            if(ip1 != 'any'):
                newpolicy = newpolicy & match(srcip=ip1)
            if(port1 != 'any'):
                newpolicy = newpolicy & match(srcport=port1)
            if(ip2 != 'any'):
                newpolicy = newpolicy & match(dstip=ip2)
            if(port2 != 'any'):
                newpolicy = newpolicy & match(dstport=port2)

            # join with the old policy
            self.policy = union([ newpolicy >> fwd(OFPP_NORMAL) + self.policy  ])

        # add rules to the policy to explicitly allow ICMP and ARP traffic to passthrough
        self.policy =  union([
            (match(protocol=pkt.ipv4.ICMP_PROTOCOL,ethtype=pkt.ethernet.IP_TYPE) >> fwd(OFPP_NORMAL)) + 
            (match(protocol=pkt.arp.REQUEST,     ethtype=pkt.ethernet.ARP_TYPE) >>  fwd(OFPP_NORMAL))+
            (match(protocol=pkt.arp.REPLY,       ethtype=pkt.ethernet.ARP_TYPE) >>  fwd(OFPP_NORMAL))+
            (match(protocol=pkt.arp.REV_REQUEST, ethtype=pkt.ethernet.ARP_TYPE) >>  fwd(OFPP_NORMAL))+
            (match(protocol=pkt.arp.REV_REPLY,   ethtype=pkt.ethernet.ARP_TYPE) >>  fwd(OFPP_NORMAL))+
            self.policy ])   
        print self.policy

def main(configuration=""):
    # read config file
    print configuration
    global config
    config=configuration
    # call AddRule(dstip, dstport, srcport, srcport)
    print firewall()
    return firewall() #mac_learner()
    # was flood()
