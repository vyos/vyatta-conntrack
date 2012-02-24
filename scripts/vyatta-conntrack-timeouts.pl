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
    print "removing with $rule_string and $timeout_policy\n";
    # function to apply the policy and then apply the policy to
    # the iptables rule. 
    # Do nothing as of now. 
}
sub apply_timeout_policy {
    # function to apply the policy and then apply the policy to
    # the iptables rule. 
    # Do nothing as of now. 
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

