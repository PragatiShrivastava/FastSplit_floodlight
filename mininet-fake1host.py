#!/usr/bin/python
"""
This example creates an attacker MITM host in mininet topology.
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, TCLink

 

def topology():

    "Create a network."

    net = Mininet( controller=RemoteController, link=TCLink, switch=OVSKernelSwitch )

    print "*** Creating nodes"
    h1 = net.addHost( 'h1', mac='00:00:00:00:00:01')
    h2 = net.addHost( 'h2', mac='00:00:00:00:00:02' )
    h3 = net.addHost( 'h3', mac='00:00:00:00:00:03', lan =2 )
    s1 = net.addSwitch( 's1', listenPort=6673, mac='00:00:00:00:00:04', protocols='OpenFlow10')
    s2 = net.addSwitch( 's2', listenPort=6674, mac='00:00:00:00:00:05', protocols='OpenFlow10')
    c1 = net.addController( 'c1', controller=RemoteController, ip='127.0.0.1', port=6633 )

    print "*** Creating links"

    net.addLink(s1, h1)
    net.addLink(s2, h2)
    " Create an attacker host h3 as mitm"
    Link(h3, s1, intfName1='h3-eth0')
    Link(h3, s2, intfName1='h3-eth1')
    "If no mitm host in the link then crate a direct link by uncommenting next line"
    #net.addLink(s1,s2)

    print "*** Starting network"
    net.build()
    c1.start()
    s1.start( [c1] )
    s2.start( [c1] )
	
    # commented lines run raw socket at host h3 for relay initialization"
    #h3.cmd('gcc -pthread raw_scoket_mini.c')
    #h3.cmd('./a.out')

    print "*** Running CLI"
    CLI( net )

    print "*** Stopping network"
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()




