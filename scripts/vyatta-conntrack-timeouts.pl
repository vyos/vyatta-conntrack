#!/usr/bin/perl

use lib "/opt/vyatta/share/perl5";
use warnings;
use strict;

use Vyatta::Config;
use Vyatta::Conntrack::RuleCT;
use Vyatta::IpTables::AddressFilter;
use Getopt::Long;
use Vyatta::Zone;
use Sys::Syslog qw(:standard :macros);

#for future use when v6 timeouts need to be set
my %cmd_hash = ( 'ipv4'        => 'iptables',
		 'ipv6'   => 'ip6tables');

my ($create, $delete, $update);

GetOptions("create=s"        => \$create,
           "delete=s"        => \$delete,
           "update=s"        => \$update,
);

update_config();

sub remove_timeout_policy {
    my ($rule_string, $timeout_policy) = @_;
    my @tokens = split (' ', $timeout_policy);
    # First remove the iptables rules before removing policy.
    my $iptables_cmd1 = "iptables -D PREROUTING -t raw $rule_string -j CT --timeout $tokens[0]";
    my $iptables_cmd2 = "iptables -D OUTPUT -t raw $rule_string -j CT --timeout $tokens[0]";
    my $nfct_timeout_cmd = "nfct-timeout remove $timeout_policy"; 
    print "$iptables_cmd1\n$iptables_cmd2\n";
    print "$nfct_timeout_cmd\n";
}

# nfct-timeout create policy1 tcp established 1200 close-wait 100 fin-wait 10
# iptables -I PREROUTING -t raw -s 1.1.1.1 -d 2.2.2.2 -j CT --timeout policy1
sub apply_timeout_policy {
    my ($rule_string, $timeout_policy) = @_;
    my $nfct_timeout_cmd = "nfct-timeout create $timeout_policy"; 
    my @tokens = split (' ', $timeout_policy);
    my $iptables_cmd1 = "iptables -I PREROUTING -t raw $rule_string -j CT --timeout $tokens[0]";
    my $iptables_cmd2 = "iptables -I OUTPUT -t raw $rule_string -j CT --timeout $tokens[0]";

    print "$nfct_timeout_cmd\n";
    print "$iptables_cmd1\n$iptables_cmd2\n";
}


sub update_config {
  my $config = new Vyatta::Config;
  my %rules = (); #hash of timeout config rules  
  my $iptables_cmd = $cmd_hash{'ipv4'};

  $config->setLevel("system conntrack timeout custom rule");
  %rules = $config->listNodeStatus();
  foreach my $rule (sort keys %rules) { 
    if ("$rules{$rule}" eq 'static') {
    } elsif ("$rules{$rule}" eq 'added') {      
      my $node = new Vyatta::Conntrack::RuleCT;
      my ($rule_string, $timeout_policy);
      $node->setup("system conntrack timeout custom rule $rule");
      $rule_string = $node->rule();
      $timeout_policy = $node->get_policy_command(); #nfct-timeout command string
      apply_timeout_policy($rule_string, $timeout_policy);
    } elsif ("$rules{$rule}" eq 'changed') {
      my $node = new Vyatta::Conntrack::RuleCT;
      $node->setup("system conntrack timeout custom rule $rule");
    } elsif ("$rules{$rule}" eq 'deleted') {
      my $node = new Vyatta::Conntrack::RuleCT;
      my ($rule_string, $timeout_policy);
      $node->setupOrig("system conntrack timeout custom rule $rule");
      $rule_string = $node->rule();
      $timeout_policy = $node->get_policy_command(); #nfct-timeout command string
      remove_timeout_policy($rule_string, $timeout_policy);
    }  
  }
}

