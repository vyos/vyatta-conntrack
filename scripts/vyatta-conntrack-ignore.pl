#!/usr/bin/perl

use lib "/opt/vyatta/share/perl5";
use warnings;
use strict;

use Vyatta::Config;
use Vyatta::Conntrack::RuleCT;
use Vyatta::Conntrack::RuleIgnore;
use Vyatta::IpTables::AddressFilter;
use Vyatta::Conntrack::ConntrackUtil;
use Getopt::Long;
use Vyatta::Zone;
use Sys::Syslog qw(:standard :macros);

#for future use when v6 timeouts need to be set
my %cmd_hash = ( 'ipv4'        => 'iptables',
		 'ipv6'   => 'ip6tables');
# Enable printing debug output to stdout.
my $debug_flag = 0;

# Enable sending debug output to syslog.
my $syslog_flag = 0;
my $nfct = "sudo /usr/sbin/nfct";
my ($create, $delete, $update);
my $CTERROR = "Conntrack timeout error:";
GetOptions("create=s"        => \$create,
           "delete=s"        => \$delete,
           "update=s"        => \$update,
);

update_config();

openlog("vyatta-conntrack", "pid", "local0");

sub remove_ignore_policy {
    my ($rule_string) = @_;
#    my $iptables_cmd1 = "iptables -D VYATTA_CT_TIMEOUT -t raw $rule_string -j CT --timeout $tokens[0]";
 #   my $iptables_cmd2 = "iptables -D VYATTA_CT_TIMEOUT -t raw $rule_string -j RETURN";
 #   run_cmd($iptables_cmd2);
 #   if ($? >> 8) {
  #    print "$CTERROR failed to run $iptables_cmd2\n";    
      #dont exit, try to clean as much. 
  #  }
  #  run_cmd($iptables_cmd1);
  #  if ($? >> 8) {
  #    print "$CTERROR failed to run $iptables_cmd1\n";    
  #  }
}

sub apply_ignore_policy {
 #   my ($rule_string, $timeout_policy, $rule, $num_rules) = @_;
    # insert at num_rules + 1 as there are so many rules already. 
 #  my $iptables_cmd1 = "iptables -I VYATTA_CT_TIMEOUT $num_rules -t raw $rule_string -j CT --timeout $tokens[0]";
 # $num_rules +=1;
 #   my $iptables_cmd2 = "iptables -I VYATTA_CT_TIMEOUT $num_rules -t raw $rule_string -j RETURN";
 #   run_cmd($nfct_timeout_cmd);
 #  if ($? >> 8) {
 #     print "$CTERROR failed to run $nfct_timeout_cmd\n";    
 #     exit 1; 
 #   }
 #  run_cmd($iptables_cmd1);
 #   if ($? >> 8) {
 #   #cleanup the policy before exit. 
 #    run_cmd("nfct timeout delete policy_timeout_$rule");   
 #    print "$CTERROR failed to run $iptables_cmd1\n";    
 #    exit 1; 
 #  }
}

sub handle_rule_creation {
  my ($rule, $num_rules) = @_;
  my $node = new Vyatta::Conntrack::RuleIgnore;
  my ($rule_string, $timeout_policy);

  print "handle_rule_creation\n";
  do_interface_check($rule);
  $node->setup("system conntrack ignore rule $rule");
  $rule_string = $node->rule();
  #apply_ignore_policy($rule_string, $rule, $num_rules);
}

# mandate only one interface configuration per rule
sub do_interface_check {
  my ($rule) = @_;
  my $config = new Vyatta::Config;
  my $intf_nos = $config->listNodes("system conntrack ignore rule $rule inbound-interface");
  if (($intf_nos > 1)) {
    Vyatta::Config::outputError(["Conntrack"], "Conntrack config error: configure at most one inbound interface in rule $rule");
    exit 1;
  }
}

sub handle_rule_modification {
  my ($rule, $num_rules) = @_;
  print "handle_rule_modification\n";
  do_interface_check($rule);
  handle_rule_deletion($rule);
  handle_rule_creation($rule, $num_rules);
}

sub handle_rule_deletion {
  my ($rule) = @_;
  my $node = new Vyatta::Conntrack::RuleIgnore;
  my ($rule_string);
  print "handle_rule_deletion\n";
  $node->setupOrig("system conntrack ignore rule $rule");
  $rule_string = $node->rule();
  remove_ignore_policy($rule_string);
}

sub numerically { $a <=> $b; }

sub update_config {
  my $config = new Vyatta::Config;
  my %rules = (); #hash of ignore config rules  
  my $iptables_cmd = $cmd_hash{'ipv4'};

  $config->setLevel("system conntrack ignore rule");
  %rules = $config->listNodeStatus();

  my $iptablesrule = 1;
  foreach my $rule (sort numerically keys %rules) { 
    if ("$rules{$rule}" eq 'static') {
      $iptablesrule+=2;
    } elsif ("$rules{$rule}" eq 'added') {      
        handle_rule_creation($rule, $iptablesrule);
        $iptablesrule+=2;
    } elsif ("$rules{$rule}" eq 'changed') {
        handle_rule_modification($rule, $iptablesrule);
        $iptablesrule+=2;
    } elsif ("$rules{$rule}" eq 'deleted') {
        handle_rule_deletion($rule);
    }  
  }
}

