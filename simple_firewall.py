"""
Team 5 - Ben Boren, Erin Lanus, Matt Welch
simple_firewall.py reimplements the firewall-like functionality in the 
previous Firewall.py POX module. This is a reimplementation in Pyretic.
"""

from pox.lib.addresses import *

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.modules.mac_learner import mac_learner
import pox.lib.packet as pkt

import inspect

OFPP_NORMAL = 0xfffa    # Process with normal L2/L3 switching.
DEBUGMODE=True

firewallDict = {}
#reactivePolicy = DynamicPolicy()
class ReactiveRuleQuery(DynamicPolicy):
    def AddReactiveRule(self,pkt_in):
        #DEBUGING: 
        #print inspect.stack()
        #if rule in config file
        print "DDEBUG: AddReactiveRule(): pkt_in=\n",pkt_in
        global DEBUGMODE
        global firewallDict
        #global reactivePolicy
        flag = False
        packet_proto = pkt_in['protocol']
        print "DDEBUG: AddReactiveRule(): Packet protocol = ",packet_proto
        if packet_proto == pkt.ipv4.TCP_PROTOCOL:
            print "DDEBUG: AddReactiveRule(): inside if-then"
            for rule in firewallDict.keys():
                srcip, srcport, dstip, dstport = rule
                print "DDEBUG: AddReactiveRule(): rule = :",rule
                if DEBUGMODE:
                    print type(str(pkt_in['srcip'])), str(pkt_in['srcip'])
                    print type(pkt_in['srcport']), pkt_in['srcport']
                    print type(pkt_in['dstip']), pkt_in['dstip']
                    print type(pkt_in['dstport']), pkt_in['dstport']
                    print type(srcip), srcip
                # attempt tp match on a forward rule
                if str(pkt_in['srcip']) == srcip or srcip == 'any':
                    print "SRCIP matches ",srcip
                    if str(pkt_in['srcport']) == srcport or srcport == 'any':
                        print "SRCPORT matches ",srcport
                        if str(pkt_in['dstip']) == dstip or dstip == 'any':
                            print "DSTIP matches ",dstip
                            if str(pkt_in['dstport']) == dstport or dstport == 'any':
                                print "DSTPORT matches ",dstport
                                flag = True
                                break
        print flag
        if  flag == True:
            # add the reactive rulpv4.TCP_PROTOCOL
            # e.g. 10.0.0.7:35463 --> 10.0.0.6:6666
            # ret: 10.0.0.6:6666 --> 10.0.0.7:35463
            print "DDEBUG: AddReactiveRule(): adding rule for : ", pkt_in
            # install "reverse" rule, i.e. B->A
            self.policy = ( match(srcip=pkt_in['dstip'],srcport=pkt_in['dstport'],
                dstip=pkt_in['srcip'],dstport=pkt_in['srcport'],
                protocol=pkt.ipv4.TCP_PROTOCOL, ethtype=pkt.ethernet.IP_TYPE) >> 
                xfwd(OFPP_NORMAL) ) + self.policy
        print "DDEBUG: AddReactiveRule() complete"
        #return reactivePolicy
    
    #def ReactiveRuleQuery():
    def __init__(self):
        #Initialize the ReactiveRules
        print "__init__(): initializing ReactiveRuleQuery"
        super(ReactiveRuleQuery,self).__init__()

        self.query = packets(limit=1,group_by=['srcip','srcport','dstip','dstport'])#
        print "QUERY::",self.query
        #match(protocol=pkt.ipv4.TCP_PROTOCOL, ethtype=pkt.ethernet.IP_TYPE) >> self.query
        self.query.register_callback(self.AddReactiveRule)

        self.policy=self.query
        print "DDEBUG: ReactiveRuleQuery __init_() done"
        #return query

class firewall(DynamicPolicy):
    def __init__(self):
        #Initialize the firewall
        print "__init__(): initializing firewall"
        global firewallDict
#        firewallDict = {}
        super(firewall,self).__init__(true)

        # push rules from the configuration file
        global config
        fin = open(config)
        for line in fin:
            rule = line.split()
            print "__init__(): \n", rule
            if rule[1] != 'any':
                rule[1] = int(rule[1])
            if rule[3] != 'any':
                rule[3] = int(rule[3])
            if (len(rule) > 0) : # only make a rule if the line is not empty
                self.AddRule(rule[0], rule[1], rule[2], rule[3])
                print "__init__():  Adding rule for: <",rule,">"
                #config.append(rule)
            if (False):
                print "__init__(): \n", config   # for everline in config file
    
        # 0.0.0.0/0 is the wildcard for the ANY IP address match
        # can add rules hardcoded 
#        self.AddRule('10.0.0.5',5555,'any','any')
        print "__init__(): \n", firewallDict
        self.update_policy()


    def AddRule(self, ip1, port1, ip2, port2):
        global firewallDict
        firewallDict[(ip1, port1, ip2, port2)] = True
        print "AddRule(): Adding Firewall rule in %s:%s -  %s:%s" % (ip1 , port1 , ip2 , port2)

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
        global firewallDict
        # create a prototype rule specifying the ethertype and TCP
        protomatch = match(protocol=pkt.ipv4.TCP_PROTOCOL ) & match(ethtype=pkt.ethernet.IP_TYPE)
        # loop through the rules in the dictionary, unioning them with the existing policy
        for (ip1, port1, ip2, port2) in firewallDict.keys(): 
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
            self.policy = (newpolicy >> xfwd(OFPP_NORMAL)) + self.policy

        # add rules to the policy to explicitly allow ICMP and ARP traffic to passthrough
        self.policy =  union([
            (match(protocol=pkt.ipv4.ICMP_PROTOCOL,ethtype=pkt.ethernet.IP_TYPE) >> xfwd(OFPP_NORMAL)) + 
            (match(protocol=pkt.arp.REQUEST,     ethtype=pkt.ethernet.ARP_TYPE) >>  xfwd(OFPP_NORMAL))+
            (match(protocol=pkt.arp.REPLY,       ethtype=pkt.ethernet.ARP_TYPE) >>  xfwd(OFPP_NORMAL))+
            (match(protocol=pkt.arp.REV_REQUEST, ethtype=pkt.ethernet.ARP_TYPE) >>  xfwd(OFPP_NORMAL))+
            (match(protocol=pkt.arp.REV_REPLY,   ethtype=pkt.ethernet.ARP_TYPE) >>  xfwd(OFPP_NORMAL))+
            self.policy ])   
        print "update_policy(): \n", self.policy

def main(configuration=""):
    # read config file
    print "main(): \n", configuration
    global config
    #global reactivePolicy
    config=configuration
    return( firewall() + (match(protocol = pkt.ipv4.TCP_PROTOCOL) >> ReactiveRuleQuery() ))#  
