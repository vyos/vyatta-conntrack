#!/usr/bin/perl

use lib "/opt/vyatta/share/perl5";
use warnings;
use strict;

use Vyatta::Config;
use Vyatta::Conntrack::ConntrackUtil;
use Vyatta::IpTables::Mgr;
use Getopt::Long;
use Sys::Syslog qw(:standard :macros);


#for future 
my %cmd_hash = ( 'ipv4'        => 'iptables',
		 'ipv6'   => 'ip6tables');

my $nfct = "sudo /opt/vyatta/sbin/nfct";
my ($enable_sqlnet, $disable_sqlnet, $enable_nfs, $disable_nfs);
my $CTERROR = "Conntrack error:";

GetOptions('enable_sqlnet=s'        => \$enable_sqlnet,
           'disable_sqlnet=s'        => \$disable_sqlnet,
           'disable_nfs=s'        => \$disable_nfs,
           'enable_nfs=s'        => \$enable_nfs,
);

# subroutine to add helper rule to VYATTA_CT_HELPER chain.
sub 
add_helper_to_chain {
  my ($module) = @_;
  my $iptables_cmd = $cmd_hash {'ipv4'}; 
  if ($module eq 'sqlnet') {
    run_cmd("$iptables_cmd -I VYATTA_CT_HELPER -t raw -p tcp --dport 1521 -j CT --helper tns");
    run_cmd("$iptables_cmd -I VYATTA_CT_HELPER -t raw -p tcp --dport 1525 -j CT --helper tns");
  } elsif ($module eq 'nfs') {
    run_cmd(" $iptables_cmd -I VYATTA_CT_HELPER -t raw -p tcp --dport 111 -j CT --helper rpc");
    run_cmd(" $iptables_cmd -I VYATTA_CT_HELPER -t raw -p udp --dport 111 -j CT --helper rpc");
  }
}

# subroutine to delete helper rule from VYATTA_CT_HELPER chain.
sub 
delete_helper_from_chain {
  my ($module) = @_;
  my $iptables_cmd = $cmd_hash {'ipv4'}; 
  if ($module eq 'sqlnet') {
    run_cmd ("$iptables_cmd -D VYATTA_CT_HELPER -t raw -p tcp --dport 1521 -j CT --helper tns");
    run_cmd ("$iptables_cmd -D VYATTA_CT_HELPER -t raw -p tcp --dport 1525 -j CT --helper tns");
  } elsif ($module eq 'nfs') {
    run_cmd("$iptables_cmd -D VYATTA_CT_HELPER -t raw -p tcp --dport 111 -j CT --helper rpc");
    run_cmd("$iptables_cmd -D VYATTA_CT_HELPER -t raw -p udp --dport 111 -j CT --helper rpc");
  }
}

# should disable the required helper module
sub disable_helper_module {
  my ($module) = @_;
 
  delete_helper_from_chain($module);
}

# should enable the required helper module
sub enable_helper_module {
  my ($module) = @_;
  add_helper_to_chain($module);
}

if (defined $enable_sqlnet){
  enable_helper_module("sqlnet"); 
} elsif (defined $disable_sqlnet) {
  disable_helper_module("sqlnet"); 
} elsif (defined $enable_nfs) {
  enable_helper_module("nfs"); 
} elsif (defined $disable_nfs) {
  disable_helper_module("nfs");
}
