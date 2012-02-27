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
# Enable printing debug output to stdout.
my $debug_flag = 0;

# Enable sending debug output to syslog.
my $syslog_flag = 0;

my ($create, $delete, $update);
my $CTERROR = "Conntrack timeout error:";
GetOptions("create=s"        => \$create,
           "delete=s"        => \$delete,
           "update=s"        => \$update,
);

update_config();

openlog("vyatta-conntrack", "pid", "local0");

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
  print "$cmd_to_run\n";

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

sub remove_timeout_policy {
    my ($rule_string, $timeout_policy) = @_;
    my @tokens = split (' ', $timeout_policy);
    # First remove the iptables rules before removing policy.
    my $iptables_cmd1 = "iptables -D PREROUTING -t raw $rule_string -j CT --timeout $tokens[0]";
    my $iptables_cmd2 = "iptables -D OUTPUT -t raw $rule_string -j CT --timeout $tokens[0]";
    my $nfct_timeout_cmd = "nfct-timeout remove $timeout_policy"; 
    run_cmd($iptables_cmd2);
    if ($? >> 8) {
      # FIXME: as of now, dont print/handle/exit as these always fail in iptables.
      #print "$CTERROR failed to run $iptables_cmd2\n";    
      #dont exit, try to clean as much. 
    }
    run_cmd($iptables_cmd1);
    if ($? >> 8) {
      # FIXME: as of now, dont print/handle/exit as these always fail in iptables.
      #print "$CTERROR failed to run $iptables_cmd1\n";    
    }
    run_cmd($nfct_timeout_cmd);
    if ($? >> 8) {
      # FIXME: as of now, dont print/handle/exit as these always fail in iptables.
      #print "$CTERROR failed to run $nfct_timeout_cmd\n";    
    }
}

# nfct-timeout create policy1 tcp established 1200 close-wait 100 fin-wait 10
# iptables -I PREROUTING -t raw -s 1.1.1.1 -d 2.2.2.2 -j CT --timeout policy1
sub apply_timeout_policy {
    my ($rule_string, $timeout_policy) = @_;
    my $nfct_timeout_cmd = "nfct-timeout create $timeout_policy"; 
    my @tokens = split (' ', $timeout_policy);
    my $iptables_cmd1 = "iptables -I PREROUTING -t raw $rule_string -j CT --timeout $tokens[0]";
    my $iptables_cmd2 = "iptables -I OUTPUT -t raw $rule_string -j CT --timeout $tokens[0]";
    run_cmd($nfct_timeout_cmd);
    if ($? >> 8) {
       # FIXME: as of now, dont print/handle/exit as these always fail in iptables.
#      print "$CTERROR failed to run $nfct_timeout_cmd\n";    
#      exit 1; 
    }
    run_cmd($iptables_cmd1);
    if ($? >> 8) {
      #cleanup the policy before exit. 
      # FIXME: as of now, dont print/handle/exit as these always fail in iptables.
#      run_cmd("nfct-timeout remove $timeout_policy");   
#      print "$CTERROR failed to run $iptables_cmd1\n";    
#      exit 1; 
    }
    run_cmd($iptables_cmd2);
    if ($? >> 8) {
      # FIXME: as of now, dont print/handle/exit as these always fail in iptables.
#      run_cmd("nfct-timeout remove $timeout_policy");   
#      run_cmd("iptables -D PREROUTING -t raw $rule_string -j CT --timeout $tokens[0]");   
#      print "$CTERROR failed to run $iptables_cmd2\n";    
#      exit 1;
    }
}

sub handle_rule_creation {
  my ($rule) = @_;
  my $node = new Vyatta::Conntrack::RuleCT;
  my ($rule_string, $timeout_policy);
  do_protocol_check($rule);
  $node->setup("system conntrack timeout custom rule $rule");
  $rule_string = $node->rule();
  $timeout_policy = $node->get_policy_command(); #nfct-timeout command string
  apply_timeout_policy($rule_string, $timeout_policy);
}

# we mandate only one protocol configuration per rule
sub do_protocol_check {
  my ($rule) = @_;
  my $config = new Vyatta::Config;
  my $protocol_nos = $config->listNodes("system conntrack timeout custom rule $rule protocol");
  if (($protocol_nos > 1) or ($protocol_nos < 1)) {
    Vyatta::Config::outputError(["Conntrack"], "Conntrack config error: please configure exactly one protocol in rule $rule");
    exit 1;
  }
}

sub handle_rule_modification {
  my ($rule) = @_;
  do_protocol_check($rule);
  handle_rule_deletion($rule);
  handle_rule_creation($rule);
}

sub handle_rule_deletion {
  my ($rule) = @_;
  my $node = new Vyatta::Conntrack::RuleCT;
  my ($rule_string, $timeout_policy);
  $node->setupOrig("system conntrack timeout custom rule $rule");
  $rule_string = $node->rule();
  $timeout_policy = $node->get_policy_command(); #nfct-timeout command string
  remove_timeout_policy($rule_string, $timeout_policy);
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
        handle_rule_creation($rule);
    } elsif ("$rules{$rule}" eq 'changed') {
        handle_rule_modification($rule);
    } elsif ("$rules{$rule}" eq 'deleted') {
        handle_rule_deletion($rule);
    }  
  }
}

