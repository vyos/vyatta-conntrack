package Vyatta::Conntrack::Config;

use strict;
use warnings;

use lib "/opt/vyatta/share/perl5";
use Vyatta::Config;
use Vyatta::TypeChecker;
use NetAddr::IP;

my %fields = (
   _udp		=> undef,
   _tcp 	=> undef,
   _icmp	=> undef,
   _other	=> undef, 
   _udp_new     => undef,
   _udp_update  => undef,
   _udp_destroy => undef,
   _tcp_new	=> undef, 
   _tcp_update	=> undef, 
   _tcp_srec	=> undef, 
   _tcp_est	=> undef, 
   _tcp_fwait   => undef, 
   _tcp_cwait   => undef, 
   _tcp_lack   => undef, 
   _tcp_twait   => undef, 
   _tcp_destroy => undef,
   _icmp_new	=> undef, 
   _icmp_update  => undef,
   _icmp_destroy => undef,
   _other_new	=> undef, 
   _other_update  => undef,
   _other_destroy => undef,
   _is_empty	  => 1,
);

my $pidfile = '/var/run/vyatta/connlogd.lock';
my $level = 'system conntrack log';

sub new {
  my $that = shift;
  my $class = ref ($that) || $that;
  my $self = {
    %fields,
  };

  bless $self, $class;
  return $self;
}

sub setup {
  my $self = shift;
  my $config = new Vyatta::Config;

  $config->setLevel("$level");
  my @nodes = $config->listNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }
  if ( $config->exists('udp') ) { $self->{_udp} = 1; }
  if ( $config->exists('tcp') ) { $self->{_tcp} = 1; }
  if ( $config->exists('icmp') ) { $self->{_icmp} = 1; }
  if ( $config->exists('other') ) { $self->{_other} = 1; }
  if ( $config->exists('udp new') ) { $self->{_udp_new} = 1; }
  if ( $config->exists('udp update') ) { $self->{_udp_update} = 1; }
  if ( $config->exists('udp destroy') ) { $self->{_udp_destroy} = 1; }
  if ( $config->exists('icmp new') ) { $self->{_icmp_new} = 1; }
  if ( $config->exists('icmp update') ) { $self->{_icmp_update} = 1; }
  if ( $config->exists('icmp destroy') ) { $self->{_icmp_destroy} = 1; }
  if ( $config->exists('other new') ) { $self->{_other_new} = 1; }
  if ( $config->exists('other update') ) { $self->{_other_update} = 1; }
  if ( $config->exists('other destroy') ) { $self->{_other_destroy} = 1; }
  if ( $config->exists('tcp new') ) { $self->{_tcp_new} = 1; }
  if ( $config->exists('tcp update') ) { $self->{_tcp_update} = 1; }
  if ( $config->exists('tcp update syn-received') ) { $self->{_tcp_srec} = 1; }
  if ( $config->exists('tcp update established') ) { $self->{_tcp_est} = 1; }
  if ( $config->exists('tcp update fin-wait') ) { $self->{_tcp_fwait} = 1; }
  if ( $config->exists('tcp update close-wait') ) { $self->{_tcp_cwait} = 1; }
  if ( $config->exists('tcp update last-ack') ) { $self->{_tcp_lack} = 1; }
  if ( $config->exists('tcp update time-wait') ) { $self->{_tcp_twait} = 1; }
  if ( $config->exists('tcp destroy') ) { $self->{_tcp_destroy} = 1; }
}

sub setupOrig {
  my $self = shift;
  my $config = new Vyatta::Config;

  $config->setLevel("$level");
  my @nodes = $config->listOrigNodes();
  if (scalar(@nodes) <= 0) {
    $self->{_is_empty} = 1;
    return 0;
  } else {
    $self->{_is_empty} = 0;
  }
  if ( $config->existsOrig('udp') ) { $self->{_udp} = 1; }
  if ( $config->existsOrig('tcp') ) { $self->{_tcp} = 1; }
  if ( $config->existsOrig('icmp') ) { $self->{_icmp} = 1; }
  if ( $config->existsOrig('other') ) { $self->{_other} = 1; }
  if ( $config->existsOrig('udp new') ) { $self->{_udp_new} = 1; }
  if ( $config->existsOrig('udp update') ) { $self->{_udp_update} = 1; }
  if ( $config->existsOrig('udp destroy') ) { $self->{_udp_destroy} = 1; }
  if ( $config->existsOrig('icmp new') ) { $self->{_icmp_new} = 1; }
  if ( $config->existsOrig('icmp update') ) { $self->{_icmp_update} = 1; }
  if ( $config->existsOrig('icmp destroy') ) { $self->{_icmp_destroy} = 1; }
  if ( $config->existsOrig('other new') ) { $self->{_other_new} = 1; }
  if ( $config->existsOrig('other update') ) { $self->{_other_update} = 1; }
  if ( $config->existsOrig('other destroy') ) { $self->{_other_destroy} = 1; }
  if ( $config->existsOrig('tcp new') ) { $self->{_tcp_new} = 1; }
  if ( $config->existsOrig('tcp update') ) { $self->{_tcp_update} = 1; }
  if ( $config->existsOrig('tcp update syn-received') ) { $self->{_tcp_srec} = 1; }
  if ( $config->existsOrig('tcp update established') ) { $self->{_tcp_est} = 1; }
  if ( $config->existsOrig('tcp update fin-wait') ) { $self->{_tcp_fwait} = 1; }
  if ( $config->existsOrig('tcp update close-wait') ) { $self->{_tcp_cwait} = 1; }
  if ( $config->existsOrig('tcp update last-ack') ) { $self->{_tcp_lack} = 1; }
  if ( $config->existsOrig('tcp update time-wait') ) { $self->{_tcp_twait} = 1; }
  if ( $config->existsOrig('tcp destroy') ) { $self->{_tcp_destroy} = 1; }
}

sub isEmpty {
  my ($self) = @_;
  return $self->{_is_empty};
}

sub isDifferentFrom {
  my ($this, $that) = @_;
  no warnings qw(uninitialized); 
  return 1 if ($this->{_udp} ne $that->{_udp});
  return 1 if ($this->{_tcp} ne $that->{_tcp});
  return 1 if ($this->{_icmp} ne $that->{_icmp});
  return 1 if ($this->{_other} ne $that->{_other});
  return 1 if ($this->{_udp_new} ne $that->{_udp_new});
  return 1 if ($this->{_udp_update} ne $that->{_udp_update});
  return 1 if ($this->{_udp_destroy} ne $that->{_udp_destroy});
  return 1 if ($this->{_tcp_new} ne $that->{_tcp_new});
  return 1 if ($this->{_tcp_update} ne $that->{_tcp_update});
  return 1 if ($this->{_tcp_srec} ne $that->{_tcp_srec});
  return 1 if ($this->{_tcp_est} ne $that->{_tcp_est});
  return 1 if ($this->{_tcp_fwait} ne $that->{_tcp_fwait});
  return 1 if ($this->{_tcp_cwait} ne $that->{_tcp_cwait});
  return 1 if ($this->{_tcp_twait} ne $that->{_tcp_twait});
  return 1 if ($this->{_tcp_lack} ne $that->{_tcp_lack});
  return 1 if ($this->{_tcp_destroy} ne $that->{_tcp_destroy});
  return 1 if ($this->{_icmp_new} ne $that->{_icmp_new});
  return 1 if ($this->{_icmp_update} ne $that->{_icmp_update});
  return 1 if ($this->{_icmp_destroy} ne $that->{_icmp_destroy});
  return 1 if ($this->{_other_new} ne $that->{_other_new});
  return 1 if ($this->{_other_update} ne $that->{_other_update});
  return 1 if ($this->{_other_destroy} ne $that->{_other_destroy});
}


sub get_command {
  my ($self) = @_;
  my $cmd = "/opt/vyatta/sbin/vyatta-conntrack-logging";
  if( $self->{_udp} ) {
    if ( $self->{_udp_new} || $self->{_udp_update} || $self->{_udp_destroy} ) { 
      if( $self->{_udp_new} ) { $cmd .= " -p udp -e NEW"; }
      if( $self->{_udp_update} ) { $cmd .= " -p udp -e UPDATES"; }
      if( $self->{_udp_destroy} ) { $cmd .= " -p udp -e DESTROY"; }
    } else {
      return (undef, 'Must specify "Event" for protocol udp');
    }
  }
  if( $self->{_icmp} ) {
    if ( $self->{_icmp_new} || $self->{_icmp_update} || $self->{_icmp_destroy} ) { 
      if( $self->{_icmp_new} ) { $cmd .= " -p icmp -e NEW"; }
      if( $self->{_icmp_update} ) { $cmd .= " -p icmp -e UPDATES"; }
      if( $self->{_icmp_destroy} ) { $cmd .= " -p icmp -e DESTROY"; }
    } else {
      return (undef, 'Must specify "Event" for protocol icmp');
    }
  }
  if( $self->{_other} ) {
    if ( $self->{_other_new} || $self->{_other_update} || $self->{_other_destroy} ) { 
      if( $self->{_other_new} ) { $cmd .= " -p other p -e NEW"; }
      if( $self->{_other_update} ) { $cmd .= " -p other -e UPDATES"; }
      if( $self->{_other_destroy} ) { $cmd .= " -p other -e DESTROY"; }
    } else {
      return (undef, 'Must specify "Event" for other protocols');
    }
  }
  if( $self->{_tcp} ) {
    if ( $self->{_tcp_new} || $self->{_tcp_update} || $self->{_tcp_destroy} ) { 
      if( $self->{_tcp_new} ) { $cmd .= " -p tcp -e NEW"; }
      if( $self->{_tcp_destroy} ) { $cmd .= " -p tcp -e DESTROY"; }
      if( $self->{_tcp_update} ) {
        if ( $self->{_tcp_srec} || $self->{_tcp_est} || $self->{_tcp_fwait} ||
        $self->{_tcp_cwait} || $self->{_tcp_twait} || $self->{_tcp_lack} ) { 
          if( $self->{_tcp_srec} ) { $cmd .= " -p tcp -e UPDATES -s SYN_RECV"; }
          if( $self->{_tcp_est} ) { $cmd .= " -p tcp -e UPDATES -s ESTABLISHED"; }
          if( $self->{_tcp_fwait} ) { $cmd .= " -p tcp -e UPDATES -s FIN_WAIT"; }
          if( $self->{_tcp_cwait} ) { $cmd .= " -p tcp -e UPDATES -s CLOSE_WAIT"; }
          if( $self->{_tcp_twait} ) { $cmd .= " -p tcp -e UPDATES -s TIME_WAIT"; }
          if( $self->{_tcp_lack} ) { $cmd .= " -p tcp -e UPDATES -s LAST_ACK"; }
        } else {
          return (undef, 'Must specify "State" for protocol tcp and event update');
        }
      }
    } else {
      return (undef, 'Must specify "Event" for protocol tcp');
    }
  } 
  return ($cmd, undef);
}

sub kill_daemon {
  my $pid;
  $pid = "cat $pidfile";
   
  system("$pid >&/dev/null");
    if ($? >> 8) {
        # daemon not running 
        return;
    }
 
  # kill daemon and its child processes 
    system("kill -HUP -`$pid` >&/dev/null");
    if ($? >> 8) {
        print STDERR "Conntrack logging error: Failed to stop daemon.\n";
        exit 1;
    }
  return; 
}
