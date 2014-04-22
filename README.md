Frenetic_Firewall
=================

SDN firewall implementation using Frenetic (https://github.com/frenetic-lang) and Pyretic (https://github.com/frenetic-lang/pyretic)

Open a terminal and launch mininet with the tested topology:
	$ sudo mn --custom ~/path/to/mininettopo.py --topo mytopo --mac --switch ovsk --controller remote

Open another terminal, navigate to the pox directory and launch the POX
controller with the Firewall module:

	$ ./pyretic.py -m p0 -v high simple_firewall --configuration="~/Frenetic_Firewall/mininet_firewall.config"

