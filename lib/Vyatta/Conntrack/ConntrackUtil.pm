#!/usr/bin/perl #
# Module:ConntrackUtil.pm 
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
# Date: Dec 2011 
# Description: Utility scripts for Vyatta conntrack 	  
#                 
#
# **** End License ****
#

package Vyatta::Conntrack::ConntrackUtil;
use Vyatta::IpTables::Mgr;
use base qw(Exporter);

sub process_protocols {
  my $proto = undef;
  my %proto_hash = ();
  my $PROTO_FILE  = '/etc/protocols';
  # do nothing if can't open
  return if (!open($proto, $PROTO_FILE));
  while (<$proto>) {
    next if (/^\s*#/);
    next if (!/^\S+\s+(\d+)\s+(\S+)\s/);
    $proto_hash{$1} = $2;
  }
  close $proto;
  return \%proto_hash;
}
our @EXPORT = qw(check_for_conntrack_hooks, process_protocols, run_cmd);

#function to find if connection tracking is enabled. 
#looks in the iptables to see if any of the features introduced
#its chain in the hooks. 
#
#returns one if any hook is present

sub check_for_conntrack_hooks {
    my @output = `sudo iptables -L -t raw`; 
    foreach(@output) {
        if (($_ =~ m/WEBPROXY_CONNTRACK/)) {
            return 1;
        }
        if (($_ =~ m/NAT_CONNTRACK/)) {
            return 1;
        }
        if (($_ =~ m/FW_CONNTRACK/)) {
            return 1;
        }
    }
}
1;

sub log_msg {
  my $message = shift;

  print "DEBUG: $message\n" if $debug_flag;
  syslog(LOG_DEBUG, "%s", $message) if $syslog_flag;
}
# Run command and capture output
# run_cmd("$iptables_cmd -t $table -F $name", 1);
# if command fails, then send output to syslog
sub run_cmd {
  my ($cmd_to_run, $redirect) = @_;

  log_msg("Running: $cmd_to_run");

  if ($redirect) {
    open (my $out, '-|',  $cmd_to_run . ' 2>&1')
        or die "Can't run command \"$cmd_to_run\": $!";
    my @cmd_out = <$out>;
  
    # if command suceeds to do nothing.
    return if (close ($out));
  
    foreach my $line (@cmd_out) {
      chomp $line;
      syslog(LOG_INFO, "%s", $line);
    }
  } else {
    system($cmd_to_run);
  }
}

# end of file
