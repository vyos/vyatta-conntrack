#!/usr/bin/perl

use lib "/opt/vyatta/share/perl5";
use warnings;
use strict;

use Vyatta::Config;
use Vyatta::IpTables::Rule;
use Vyatta::IpTables::AddressFilter;
use Vyatta::IpTables::Mgr;
use Getopt::Long;
use Vyatta::Zone;
use Sys::Syslog qw(:standard :macros);

my ($create, $delete, $update);

GetOptions("create=s"        => \$create,
           "delete=s"        => \$delete,
           "update=s"        => \$update,
);

if ($create and ($create eq 'true')) {
    print "create\n";
    # create a nfct-timeout policy based on protocol specific timers
    # check if the rule has protocol configured
    # if configured, check what the protocol is and get the appropriate timers. 
}

if ($delete and ($delete eq 'true')) {
    print "delete";
}
if ($update and ($update eq 'true')) {
    print "update";
}
