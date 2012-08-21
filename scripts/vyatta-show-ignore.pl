#!/usr/bin/perl
#
# Module: vyatta-show-conntrack.pl
#
# **** License ****
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# This code was originally developed by Vyatta, Inc.
# Portions created by Vyatta are Copyright (C) 2010 Vyatta, Inc.
# All Rights Reserved.
#
# Author: Gaurav Sinha 
# Date: Aug 2012 
# Description: 	Script to show conntrack ignore entries  
#
#
# **** End License ****
#

use Getopt::Long;
use XML::Simple;
use Data::Dumper;
use POSIX;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Conntrack::ConntrackUtil;
use Vyatta::Misc;
use warnings;
use strict;

my $format = "%-10s %-22s %-22s %-16s %-20s\n";
my $format_IPv6 = "%-10s %-40s %-40s %-16s %-20s\n";
my $href; #reference to hash containing protocol-num to name key-value pairs

sub numerically { $a <=> $b; }

sub print_ignore_rules {
  my $format_ignore_rules = "%-5s %-22s %-22s %-10s %-5s %-5s %-5s\n";
  print "\n";
  my $config = new Vyatta::Config;
  $config->setLevel("system conntrack ignore rule");
  my @rules = sort numerically $config->listOrigNodes(); 

  my @rules_in_chain = `sudo iptables -L VYATTA_CT_IGNORE -t raw -nv`;
  if (!(@rules_in_chain)){
    die "Error: no ignore rules configured\n";
  }
  printf($format_ignore_rules, 'rule', 'source', 'destination', 'protocol', 'Interface [IN]', 'packets', 'bytes');
  splice(@rules_in_chain, 0, 2); 
  my $rulecount = 0;
  foreach (@rules) {
    my $sourceAddress = "any";
    my $sourcePort = "any";
    my $destinationAddress = "any";
    my $destPort = "any";
    my $protocol = "any";
    my $interface = "any";

    $config->setLevel("system conntrack ignore rule $_"); 

    $sourceAddress = $config->returnOrigValue("source address"); 
    $sourcePort = $config->returnOrigValue("source port"); 
    $destinationAddress = $config->returnOrigValue("destination address"); 
    $destPort = $config->returnOrigValue("destination port"); 
    $protocol = $config->returnOrigValue("protocol"); 
    $interface = $config->returnOrigValue("inbound-interface"); 

    if (!defined ($sourcePort)) { $sourcePort = "any";} 
    if (!defined ($sourceAddress)) { $sourceAddress = "any";} 
    if (!defined ($destPort)) { $destPort = "any";} 
    if (!defined ($destinationAddress)) { $destinationAddress = "any";} 
    if (!defined ($protocol)) { $protocol = "any";} 
    if (!defined ($interface)) { $interface = "any";} 

    $sourceAddress .= ":$sourcePort";
    $destinationAddress .= ":$destPort";
 
    my $rule_ipt = $rules_in_chain[$rulecount];
    my @words = split(' ', $rule_ipt); 

    printf ($format_ignore_rules, $_, $sourceAddress, $destinationAddress, $protocol, $interface, $words[0], $words[1]);     
    $rulecount++;
  }  
}
#
# main
#

print_ignore_rules();
# end of file
