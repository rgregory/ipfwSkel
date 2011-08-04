#!/usr/bin/perl -W

# ipfwSkel.pl - output skeleton ipfw rulesets
#
# Copyright (c) 2005 Roger Gregory <rtgregory@gmail.com>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# $Date: 2005-12-29 11:47:52 -0500 (Thu, 29 Dec 2005) $:

# Grab command line options
#
use Getopt::Long;
GetOptions("tcp=s"      => \@tcp,
        "udp=s"         => \@udp,
        "queue=s"       => \@queue,
        "limit=s"       => \$limit,
        "icmp=s"        => \@icmp,
        "trusted=s"     => \@trusted );

@tcp = split(/,/,join(',',@tcp));
@udp = split(/,/,join(',',@udp));
@trusted = split(/,/,join(',',@trusted));
@queue = split(/,/,join(',',@queue));
@icmp = split(/,/,join(',',@icmp));

$version ="0.1";

# How ugly is this?
#
unless (@tcp||@udp||@trusted||@icmp||@queue) { &usage(); exit; }

$IPFW="/sbin/ipfw";

# Fool!
#
if (@queue) { die "ERROR: No limit associated with --queue \n" unless ($limit) };

sub usage() {
print <<DUMP
ipfwSkel creates skeleton ipfw dynamic rulesets which may be useful for the overworked
sysadmin. It's not particularly clever, but does support single queue creation,

Usage: ipfSkel.pl <options>
Options:
--tcp       tcp ports to open to the world
--udp       udp ports top open to the world
--trusted   trusted ip or netrange to allow complete access
--queue     allow inbound tcp destination ports (bandwidth limited)
--limit     associated limit in kbits/sec for --queue ports
--icmp      icmp codetypes to allow (defaults to 3,4,11)

Example: Open ports 22 to the world and trust 1.2.3.0/24
./ipfwSkel.pl --tcp 22 --trusted 1.2.3.0/24 > ipfw.rules

Create a 300kbits/sec limit for port 80
./ipfwSkel.pl --queue 80 --limit 300 > ipfw.rules

DUMP
;
}

# Header
#
print "# ipfw ruleset - created by ipfwSkel.pl $version\n",
      "#\n",
      "\n\n";

# Flush existing entries.
#
print "# Flush all existing rules\n",
      "#\n",
      "$IPFW -f flush\n";

# Create bandwidth pipe as needed
#
if (@queue) {
    print "\n# Bandwidth queues\n",
          "#\n";

    if ($limit) {
        $limit = $limit . "kbit/s";
        print "$IPFW pipe 10 config bw $limit\n";
    }
}

# Localhost connections
#
print "\n# Localhost is special\n",
      "#\n",
      "$IPFW -q add allow ip from any to any via lo0\n";

# Drop inbound packets with nosensical flags
#
print "\n# drop mysterious connections\n",
      "#\n",
      "$IPFW -q add deny log tcp from any to any in tcpflags syn,fin\n";

# ICMP
#
print "\n# Allow specific ICMP types\n",
      "#\n";
      
if ( ! @icmp) {
      print "$IPFW -q add allow icmp from any to any icmptype 3 keep-state\n",
            "$IPFW -q add allow icmp from any to any icmptype 4 keep-state\n",
            "$IPFW -q add allow icmp from any to any icmptype 11 keep-state\n";
} else {
    foreach $ping (@icmp) {
        print "$IPFW -q add allow icmp from any to any icmptype $ping keep-state\n";
        }
}
    

# Trusted networks
#
if (@trusted) {
    print "\n# Trusted network(s) - unfiltered access\n",
          "#\n";
 
    foreach $foo (@trusted) {
        print "$IPFW -q add allow ip from $foo to me in\n",
              "$IPFW -q add allow ip from me to $foo out\n";
    }
}

# Verify inbound packet against state table, drop
# ACK's if not associated with valid state entry.
#
print "\n# Check state and drop unmatched established connections\n",
      "#\n",
      "$IPFW -q add check-state\n",
      "$IPFW -q add deny tcp from any to me established in\n";

# Loop through defined public services, add
# rule if input is sane or not previously added
#
if (@tcp|@udp) {
    print "\n# Publically allowed services\n",
          "#\n";
        
    foreach $tcp_ports (@tcp) {
        unless (exists($tcpseen{$tcp_ports})) {
            $tcpseen{$tcp_ports} = $tcp_ports;
            unless (($tcp_ports =~ /\D/) || ($tcp_ports > 65535) || ($tcp_ports < 1)) {
                print "$IPFW -q add allow tcp from any to me $tcp_ports in setup keep-state\n";
            }
        }
    }

    foreach $udp_ports (@udp) {
        unless (exists($udpseen{$udp_ports})) {
            $udpseen{$udp_ports} = $udp_ports;
            unless (($udp_ports =~ /\D/) || ($udp_ports > 65535) || ($udp_ports < 1)) {
                print "$IPFW -q add allow udp from any to me $udp_ports in keep-state\n";
            }
        }
    }
}

# Add defined queue ports if input is sane or not
# previously added
#
if (@queue) {
    print "\n# Bandwidth managed\n",
          "#\n";

    if ($limit) {
        foreach $qport (@queue) {
            unless (exists($tcpseen{$qport})) {
                unless (($qport =~ /\D/) || ($qport > 65535) || ($qport < 1)) {
                    print "$IPFW -q add allow tcp from any to me $qport setup keep-state\n";
                }
            }
            unless (exists($queued{$qport})) {
                unless (($qport =~ /\D/) || ($qport > 65535) || ($qport < 1)) {
                    print "$IPFW -q add queue 10 tcp from me $qport to any out\n";
                    $queued{$qport} = $qport;
                }
            }
        }
    }
}
        

# Keep state outbound
#
print "\n# keep state on outgoing connections\n",
      "#\n",
      "$IPFW -q add allow ip from me to any out keep-state\n";
 
# Last resort
#
print "\n# Drop everything else\n",
      "#\n",
      "$IPFW -q add deny log ip from any to any\n";
