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
my $CTERROR = "Conntrack Timeout Error:";
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

sub rule {
  my ( $self ) = @_;
  my ($rule, $srcrule, $dstrule, $err_str);
  my $tcp_and_udp = 0;
  # set CLI rule num as comment
  my @level_nodes = split (' ', $self->{_comment});
  $rule .= "-m comment --comment \"$level_nodes[2]-$level_nodes[5]\" ";
  ($srcrule, $err_str) = $src->rule();
  if (defined($err_str)) {
        Vyatta::Config::outputError(["Conntrack"], "Conntrack config error: $err_str");
        exit 1;
  }
  ($dstrule, $err_str) = $dst->rule();
  if (defined($err_str)) {
        Vyatta::Config::outputError(["Conntrack"], "Conntrack config error: $err_str");
        exit 1;
  }
  $rule .= " $srcrule $dstrule ";
  return $rule;
}

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

  #FIXME: AddressFilter.pm needs a change to accomodate other and
  # icmp protocols as it does port checks unconditionally. 
  $src->$addr_setup("$level source");
  $src->{_protocol} = $self->{_protocol};#needed to use address filter
  if ( (($src->{_protocol} eq 'icmp') or ($src->{_protocol} eq 'other')) and (defined($src->{_port})) ) { 
    die "Error: Cannot specify port with protocol $src->{_protocol}\n"; 
  }
  $dst->$addr_setup("$level destination");
  $dst->{_protocol} = $self->{_protocol};#needed to use address filter
  if ( (($dst->{_protocol} eq 'icmp') or ($dst->{_protocol} eq 'other')) and (defined($dst->{_port})) ) { 
    die "Error: Cannot specify port with protocol $dst->{_protocol}\n"; 
  }

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
      $command .= " icmp $self->{_icmp}";
  } elsif ($self->{_protocol} eq 'other') {  
      $command .= " other $self->{_other}";
    }
  print "\n $command\n\n";
  return $command;
}



1;

# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 2
# End:
