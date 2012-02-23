# 
# The timeouts are implemented using nfct-timeout policies that are
# later applied to the corresponding iptables rules. The rules and 
# policies are distinguished based on the rule number.   

package Vyatta::Conntrack::RuleCT;

use strict;
use Vyatta::Config;
require Vyatta::IpTables::AddressFilter;

my $src = new Vyatta::IpTables::AddressFilter;
my $dst = new Vyatta::IpTables::AddressFilter;

my %fields = (
  _rule_number => undef,
  _protocol    => undef, 
  _tcp => {
     _close => undef,
     _close_wait => undef,
     _established => undef,
     _fin_wait => undef,
     _last_ack => undef,
     _syn_sent => undef,
     _syn_recv => undef,
     _time_wait => undef,
     },
     _udp => {
     _other => undef,
     _stream => undef,    
     },
     _other => undef,
     _icmp => undef , 
     _comment => undef,
);

my %dummy_rule = (
  _rule_number => 10000,
  _protocol    => undef, 
  _tcp => {
     _close => undef,
     _close_wait => undef,
     _established => undef,
     _fin_wait => undef,
     _last_ack => undef,
     _syn_sent => undef,
     _syn_recv => undef,
     _time_wait => undef,
     },
     _udp => {
     _other => undef,
     _stream => undef,    
     },
     _other => undef,
     _icmp => undef , 
     _comment => undef,
);

my $DEBUG = 'false';

sub new {
  my $that = shift;
  my $class = ref ($that) || $that;
  my $self = {
    %fields,
  };

  bless $self, $class;
  return $self;
}

sub setupDummy {
  my ($self, $level) = @_;

  %{$self} = %dummy_rule;
  $src = new Vyatta::IpTables::AddressFilter;
  $dst = new Vyatta::IpTables::AddressFilter;

  # set the default policy
  my $config = new Vyatta::Config;
  $config->setLevel("$level");
}

sub setup_base {
  my ($self, $level, $val_func, $exists_func, $addr_setup) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel("$level");
  $self->{_comment} = $level;
  $self->{_rule_number} = $config->returnParent("..");
  if ($config->$exists_func("protocol tcp")) {
    $self->{_protocol} = "tcp";
    $self->{_tcp}->{_close} = $config->$val_func("protocol tcp close"); 
    $self->{_tcp}->{_close_wait} = $config->$val_func("protocol tcp close-wait"); 
    $self->{_tcp}->{_time_wait} = $config->$val_func("protocol tcp time_wait"); 
    $self->{_tcp}->{_syn_recv} = $config->$val_func("protocol tcp syn-recv"); 
    $self->{_tcp}->{_syn_sent} = $config->$val_func("protocol tcp syn-sent"); 
    $self->{_tcp}->{_last_ack} = $config->$val_func("protocol tcp last-ack"); 
    $self->{_tcp}->{_fin_wait} = $config->$val_func("protocol tcp fin-wait"); 
    $self->{_tcp}->{_established} = $config->$val_func("protocol tcp established"); 
  } elsif ($config->$exists_func("protocol icmp")) {
    $self->{_protocol} = "icmp";
    $self->{_icmp} = $config->$val_func("protocol icmp");
  } elsif ($config->$exists_func("protocol udp")) {
    $self->{_protocol} = "udp";
    $self->{_udp}->{_other} = $config->$val_func("protocol udp other"); 
    $self->{_udp}->{_stream} = $config->$val_func("protocol udp stream"); 
  } elsif ($config->$exists_func("protocol other")) {
    $self->{_protocol} = "other";
    $self->{_other} = $config->$val_func("protocol other");
  }

  $src->$addr_setup("$level source");
  $dst->$addr_setup("$level destination");

  return 0;
}

sub setup {
  my ($self, $level) = @_;
  
  $self->setup_base($level, 'returnValue', 'exists', 'setup');
  return 0;
}

sub setupOrig {
  my ($self, $level) = @_;
  $self->setup_base($level, 'returnOrigValue', 'existsOrig', 'setupOrig');
  return 0;
}

sub print {
  my ( $self ) = @_;

  print "rulenum: $self->{_rule_number}\n" if defined $self->{_rule_number};
  print "protocol: $self->{_protocol}\n"   if defined $self->{_protocol};
  print "state: $self->{_state}\n"         if defined $self->{_state};
  $src->print();
  $dst->print();
  print "$self->{_tcp}->{_close}\n";
  print "$self->{_tcp}->{_close_wait}\n";
  print "$self->{_tcp}->{_established}\n";
  print "$self->{_tcp}->{_fin_wait}\n";
  print "$self->{_tcp}->{_syn_sent}\n";
  print "$self->{_tcp}->{_syn_recv}\n";
}

# return a string that has the nfct-timeout command to create
# a timeout policy.  
sub get_policy_command {
  my ($self ) = @_;
  my $command;
  my @level_nodes = split (' ', $self->{_comment});
  $command .= "policy_$level_nodes[2]_$level_nodes[5]";
  if ($self->{_protocol} eq 'tcp') {
    $command .= " tcp";
    if ($self->{_tcp}->{_close}) {
      $command .= " close $self->{_tcp}->{_close}"; 
    }
    if ($self->{_tcp}->{_close_wait}) {
      $command .= " close-wait $self->{_tcp}->{_close_wait}";
    }
    if ($self->{_tcp}->{_time_wait}) {
      $command .= " time-wait $self->{_tcp}->{_time_wait}"; 
    }
    if ($self->{_tcp}->{_syn_recv}) {
      $command .= " syn-recv $self->{_tcp}->{_syn_recv}"; 
    }
    if ($self->{_tcp}->{_syn_sent}) {
      $command .= " syn-sent $self->{_tcp}->{_syn_sent}"; 
    }
    if ($self->{_tcp}->{_last_ack}) {
      $command .= " last-ack $self->{_tcp}->{_last_ack}"; 
    }
    if ($self->{_tcp}->{_fin_wait}) {
      $command .= " fin-wait $self->{_tcp}->{_fin_wait}"; 
    }
    if ($self->{_tcp}->{_established}) {
      $command .= " established $self->{_tcp}->{_established}"; 
    }
  } elsif ($self->{_protocol} eq 'udp') {
      $command .= " udp";
      if ($self->{_udp}->{_other}) {
        $command .= " other $self->{_udp}->{_other}";
      }
      if ($self->{_udp}->{_stream}) {
        $command .= " stream $self->{_udp}->{_stream}";
      }
  } elsif ($self->{_protocol} eq 'icmp') {
      $command .= " icmp";
      $command .= " icmp $self->{_icmp}";
  } elsif ($self->{_protocol} eq 'other') {  
      $command .= " other";
      $command .= " other $self->{_other}";
    }
  print "\n $command\n\n";
  return $command;
}

sub rule {
  my ( $self ) = @_;
  my ($rule, $srcrule, $dstrule, $err_str);
  my $tcp_and_udp = 0;

  # set CLI rule num as comment
  my @level_nodes = split (' ', $self->{_comment});
  $rule .= "-m comment --comment \"$level_nodes[2]-$level_nodes[5]\" ";
  print "rule is $rule\n";

  # set the protocol
  if (defined($self->{_protocol})) {
    my $str    = $self->{_protocol};
    my $negate = '';
    if ($str =~ /^\!(.*)$/) {
      $str    = $1;
      $negate = '! ';
    }
    if ($str eq 'tcp_udp') {
      $tcp_and_udp = 1;
      $rule .= " $negate -p tcp "; # we'll add the '-p udp' to 2nd rule later
    } else {
      $rule .= " $negate -p $str ";
    }
  }

  my $state_str = uc (get_state_str($self));
  if ($state_str ne "") {
    $rule .= "-m state --state $state_str ";
  }

  # set tcp flags if applicable
  my $tcp_flags = undef;
  if (defined $self->{_tcp_flags}) {
   if (($self->{_protocol} eq "tcp") || ($self->{_protocol} eq "6")) {
      $tcp_flags = get_tcp_flags_string($self->{_tcp_flags});
    } else {
      return ("TCP flags can only be set if protocol is set to TCP", );
    }
  }
  if (defined($tcp_flags)) {
    $rule .= " -m tcp --tcp-flags $tcp_flags ";
  }

  # set the icmp code and type if applicable
  if (($self->{_protocol} eq "icmp") || ($self->{_protocol} eq "1")) {
   if (defined $self->{_icmp_name}) {
     if (defined($self->{_icmp_type}) || defined($self->{_icmp_code})){
      return ("Cannot use ICMP type/code with ICMP type-name", );
     }
     $rule .= "--icmp-type $self->{_icmp_name} ";
   } elsif (defined $self->{_icmp_type}) {
      $rule .= "--icmp-type $self->{_icmp_type}";
      if (defined $self->{_icmp_code}) {
        $rule .= "/$self->{_icmp_code}";
      }
      $rule .= " ";
   } elsif (defined $self->{_icmp_code}) {
      return ("ICMP code can only be defined if ICMP type is defined", );
   }
  } elsif (defined($self->{_icmp_type}) || defined($self->{_icmp_code}) 
           || defined($self->{_icmp_name})) {
     return ("ICMP type/code or type-name can only be defined if protocol is ICMP", );
  }

  # Setup ICMPv6 rule if configured
  # ICMPv6 parameters are only valid if the rule is matching on the 
  # ICMPv6 protocol ID.
  # 
  if (($self->{_protocol} eq "icmpv6") || 
      ($self->{_protocol} eq "ipv6-icmp") || 
      ($self->{_protocol} eq "58")) {
    if (defined($self->{_icmpv6_type})) {
      $rule .= "-m icmpv6 --icmpv6-type $self->{_icmpv6_type}";
    }
  }

  # add the source and destination rules
  ($srcrule, $err_str) = $src->rule();
  return ($err_str, ) if (!defined($srcrule));
  ($dstrule, $err_str) = $dst->rule();
  return ($err_str, ) if (!defined($dstrule));
  if ((grep /multiport/, $srcrule) ^ (grep /multiport/, $dstrule)) {
    if ((grep /sport/, $srcrule) && (grep /dport/, $dstrule)) {
      return ('Cannot specify multiple ports when both '
              . 'source and destination ports are specified', );
    }
  }
  $rule .= " $srcrule $dstrule ";

  return ('Cannot specify both "match-frag" and "match-non-frag"', )
    if (defined($self->{_frag}) && defined($self->{_non_frag}));
  if (defined($self->{_frag})) {
    $rule .= ' -f ';
  } elsif (defined($self->{_non_frag})) {
    $rule .= ' ! -f ';
  }

  # note: "out" is not valid in the INPUT chain.
  return ('Cannot specify both "match-ipsec" and "match-none"', )
    if (defined($self->{_ipsec}) && defined($self->{_non_ipsec}));
  if (defined($self->{_ipsec})) {
    $rule .= ' -m policy --pol ipsec --dir in ';
  } elsif (defined($self->{_non_ipsec})) {
    $rule .= ' -m policy --pol none --dir in ';
  }

  my $p2p = undef;
  if (defined($self->{_p2p}->{_all})) {
    $p2p = '--apple --bit --dc --edk --gnu --kazaa ';
  } else {
    my @apps = qw(apple bit dc edk gnu kazaa);
    foreach (@apps) {
      if (defined($self->{_p2p}->{"_$_"})) {
        $p2p .= "--$_ ";
      }
    }
  }
  if (defined($p2p)) {
    $rule .= " -m ipp2p $p2p ";
  }

  my $time = undef;
  if (defined($self->{_time}->{_utc})) {
      $time .= " --utc ";
  }
  if (defined($self->{_time}->{_startdate})) {
   my $check_date = validate_date($self->{_time}->{_startdate}, "startdate");
   if (!($check_date eq "")) {
     return ($check_date, );
   }
   $time .= " --datestart $self->{_time}->{_startdate} ";
  }
  if (defined($self->{_time}->{_stopdate})) {
   my $check_date = validate_date($self->{_time}->{_stopdate}, "stopdate");
   if (!($check_date eq "")) {
     return ($check_date, );
   }
   $time .= " --datestop $self->{_time}->{_stopdate} ";
  }
  if (defined($self->{_time}->{_starttime})) {
  return ("Invalid starttime $self->{_time}->{_starttime}.
Time should use 24 hour notation hh:mm:ss and lie in between 00:00:00 and 23:59:59", )
    if (!validate_timevalues($self->{_time}->{_starttime}, "time"));
      $time .= " --timestart $self->{_time}->{_starttime} ";
  }
  if (defined($self->{_time}->{_stoptime})) {
  return ("Invalid stoptime $self->{_time}->{_stoptime}.
Time should use 24 hour notation hh:mm:ss and lie in between 00:00:00 and 23:59:59", )
    if (!validate_timevalues($self->{_time}->{_stoptime}, "time"));
      $time .= " --timestop $self->{_time}->{_stoptime} ";
  }
  if (defined($self->{_time}->{_monthdays})) {
      my $negate = " ";
      if ($self->{_time}->{_monthdays} =~ m/^!/) {
          $negate = "! ";
          $self->{_time}->{_monthdays} = substr $self->{_time}->{_monthdays}, 1;
      }
  return ("Invalid monthdays value $self->{_time}->{_monthdays}.
Monthdays should have values between 1 and 31 with multiple days separated by commas
eg. 2,12,21 For negation, add ! in front eg. !2,12,21", )
    if (!validate_timevalues($self->{_time}->{_monthdays}, "monthdays"));
      $time .= " $negate --monthdays $self->{_time}->{_monthdays} ";
  }
  if (defined($self->{_time}->{_weekdays})) {
      my $negate = " ";
      if ($self->{_time}->{_weekdays} =~ m/^!/) {
          $negate = "! ";
          $self->{_time}->{_weekdays} = substr $self->{_time}->{_weekdays}, 1;
      }
  return ("Invalid weekdays value $self->{_time}->{_weekdays}.
Weekdays should be specified using the first three characters of the day with the
first character capitalized eg. Mon,Thu,Sat For negation, add ! in front eg. !Mon,Thu,Sat", )
    if (!validate_timevalues($self->{_time}->{_weekdays}, "weekdays"));
      $time .= " $negate --weekdays $self->{_time}->{_weekdays} ";
  }
  if (defined($time)) {
    $rule .= " -m time $time ";
  }

  my $limit = undef;
  if (defined $self->{_limit}->{_rate}) {
    my $rate_integer = $self->{_limit}->{_rate};
    $rate_integer =~ s/\/(second|minute|hour|day)//;
    if ($rate_integer < 1) {
      return ("integer value in rate cannot be less than 1", );
    }
    $limit = "--limit $self->{_limit}->{_rate} --limit-burst $self->{_limit}->{_burst}";
  }
  $rule .= " -m limit $limit " if defined $limit;

  # recent match condition SHOULD BE DONE IN THE LAST so
  # all options in $rule are copied to $recent_rule below
  my $recent_rule = undef;
  if (defined($self->{_recent_time}) || defined($self->{_recent_cnt})) {
    my $recent_rule1 = undef;
    my $recent_rule2 = undef;
    $recent_rule1 .= ' -m recent --update ';
    $recent_rule2 .= ' -m recent --set ';
    if (defined($self->{_recent_time})) {
      $recent_rule1 .= " --seconds $self->{_recent_time} ";
    }
    if (defined($self->{_recent_cnt})) {
      $recent_rule1 .= " --hitcount $self->{_recent_cnt} ";
    }
    
    $recent_rule = $rule;
    
    if ($rule =~ m/\-m\s+set\s+\-\-match\-set/) {
      # firewall group being used in this rule. iptables complains if recent
      # match condition is placed after group match conditions [see bug 5744]
      # so instead of appending recent match place it before group match
      my @split_rules = ();
      
      @split_rules = split(/(\-m\s+set\s+\-\-match\-set)/, $rule, 2);
      $rule =   $split_rules[0] . $recent_rule1 . 
                $split_rules[1] . $split_rules[2];
                
      @split_rules = split(/(\-m\s+set\s+\-\-match\-set)/, $recent_rule, 2);
      $recent_rule =    $split_rules[0] . $recent_rule2 . 
                        $split_rules[1] . $split_rules[2];
    } else {
      # append recent match conditions to the two rules needed for recent match
      $rule .= $recent_rule1;
      $recent_rule .= $recent_rule2;
    }
  }

  my $chain = $self->{_name};
  my $rule_num = $self->{_rule_number};
  my $rule2 = undef;
  # set the jump target.  Depends on action and log
  if ("$self->{_log}" eq "enable") {
    $rule2 = $rule;
    my $log_prefix = get_log_prefix($chain, $rule_num, $self->{_action});
    $rule2 .= "-j LOG --log-prefix \"$log_prefix\" ";
  }
  if ("$self->{_action}" eq "drop") {
    $rule .= "-j DROP ";
  } elsif ("$self->{_action}" eq "accept") {
    $rule .= "-j RETURN ";
  } elsif ("$self->{_action}" eq "reject") {
    $rule .= "-j REJECT ";
  } elsif ("$self->{_action}" eq 'inspect') {
    my $target = ipt_get_queue_target('SNORT');
    return ('Undefined target for inspect', ) if ! defined $target;
    $rule .= "-j $target ";
  } elsif ("$self->{_action}" eq 'modify') {
    # mangle actions
    my $count = 0;
    if (defined($self->{_mod_mark})) {
      # MARK
      $rule .= "-j MARK --set-mark $self->{_mod_mark} ";
      $count++;
    }
    if (defined($self->{_mod_dscp})) {
      # DSCP
      $rule .= "-j DSCP --set-dscp $self->{_mod_dscp} ";
      $count++;
    }
    if (defined($self->{_mod_tcpmss})) {
      # TCP-MSS
      # check for SYN flag
      if (!defined $self->{_tcp_flags} ||
	  !(($self->{_tcp_flags} =~ m/SYN/) && !($self->{_tcp_flags} =~ m/!SYN/))) {
        return ('need to set TCP SYN flag to modify TCP MSS', );
      }

      if ($self->{_mod_tcpmss} =~ m/\d/) {
        $rule .= "-j TCPMSS --set-mss $self->{_mod_tcpmss} ";
      } else {
        $rule .= "-j TCPMSS --clamp-mss-to-pmtu ";
      }
      $count++;
    }
    
    # others

    if ($count == 0) {
      return ('Action "modify" requires more specific configuration under '
              . 'the "modify" node', );
    } elsif ($count > 1) {
      return ('Cannot define more than one modification under '
              . 'the "modify" node', );
    }
  } else {
    return ("\"action\" must be defined", );
  }
  if (defined($rule2)) {
    my $tmp = $rule2;
    $rule2 = $rule;
    $rule = $tmp;
  } elsif (defined($recent_rule)) {
    $rule2 = $recent_rule;
    $recent_rule = undef;
  }

  return (undef, undef) if defined $self->{_disable};

  my ($udp_rule, $udp_rule2, $udp_recent_rule) = (undef, undef, undef);
  if ($tcp_and_udp == 1) {
    # create udp rules
    $udp_rule = $rule;
    $udp_rule2 = $rule2 if defined $rule2;
    $udp_recent_rule = $recent_rule if defined $recent_rule;
    foreach my $each_udprule ($udp_rule, $udp_rule2, $udp_recent_rule) {
      $each_udprule =~ s/ \-p tcp / -p udp / if defined $each_udprule;
    }
  }
  
  if ($DEBUG eq 'true') {
    # print all potential iptables rules that could be formed for 
    # a single CLI rule. see get_num_ipt_rules to see exact count
    print "rule :\n$rule\n" if defined $rule;
    print "rule2 :\n$rule2\n" if defined $rule2;
    print "recent rule :\n$recent_rule\n" if defined $recent_rule;
    print "udp rule :\n$udp_rule\n" if defined $udp_rule;
    print "udp rule2 :\n$udp_rule2\n" if defined $udp_rule2;
    print "udp recent rule :\n$udp_recent_rule\n" if defined $udp_recent_rule;
  }
  
  return (undef, $rule, $rule2, $recent_rule, $udp_rule, $udp_rule2, $udp_recent_rule);
}



1;

# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 2
# End:
