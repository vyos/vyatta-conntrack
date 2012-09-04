package Vyatta::Conntrack::RuleIgnore;

use strict;
use Vyatta::Config;
require Vyatta::IpTables::AddressFilter;

my $src = new Vyatta::IpTables::AddressFilter;
my $dst = new Vyatta::IpTables::AddressFilter;
my %fields = (
  _rule_number => undef,
  _protocol    => undef, 
  _comment => undef,
);

my %dummy_rule = (
  _rule_number => 10000,
  _protocol    => undef, 
     _comment => undef,
);

my $DEBUG = 'false';

sub rule {
  my ( $self ) = @_;
  my ($rule1, $rule2, $srcrule, $dstrule, $err_str);
  # set CLI rule num as comment
  my @level_nodes = split (' ', $self->{_comment});
  $rule1 .= " -m comment --comment \"$level_nodes[2]-$level_nodes[4]\" ";
  
  if (defined($self->{_interface})) {
    $rule1 .= " -i $self->{_interface} ";
  }
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
 
  if (defined($self->{_protocol})) {
    if ($self->{_protocol} eq 'tcp_udp') {
      $rule2 = $rule1;
   #break protcol as tcp and udp, two rules
      if ($self->{_protocol} =~ m/^!/) {
        $rule1 .= " ! -p  tcp";
        $rule2 .= " ! -p  udp";
      } else {
        $rule1 .= " -p tcp ";
        $rule2 .= " -p udp ";
      }
    } else {
      if ($self->{_protocol} =~ m/^!/) {
        my $protocol = substr($self->{_protocol}, 1);
        $rule1 .= " ! -p  $protocol";
      } else {
        $rule1 .= " -p $self->{_protocol}";
       }
    }
  }
  
  $rule1 .= " $srcrule $dstrule ";
  if ($rule2) {
    $rule2 .= " $srcrule $dstrule ";
  }
  return ($rule1, $rule2);
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

sub setup_base {
  my ($self, $level, $val_func, $exists_func, $addr_setup) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel("$level");
  $self->{_comment} = $level;
  $self->{_rule_number} = $config->returnParent("..");
  $self->{_interface} = $config->$val_func("inbound-interface");
  $self->{_protocol} = $config->$val_func("protocol");

  $src->$addr_setup("$level source");
  $src->{_protocol} = $self->{_protocol};#needed to use address filter

  my $rule = $self->{_rule_number};
  if (($src->{_port})) {
    if (($src->{_protocol} ne 'udp') and ($src->{_protocol} ne 'tcp')) {
      die "Error: port requires tcp / udp as protocol in rule $rule\n"; 
    }
  }

  $dst->$addr_setup("$level destination");
  $dst->{_protocol} = $self->{_protocol};#needed to use address filter

  if (($dst->{_port})) {
    if (($dst->{_protocol} ne 'udp') and ($dst->{_protocol} ne 'tcp')) {
      die "Error: port requires tcp / udp as protocol in rule $rule\n"; 
    }
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
  print "inbound interface: $self->{_interface}\n"   if defined $self->{_interface};
  $src->print();
  $dst->print();
}




1;

# Local Variables:
# mode: perl
# indent-tabs-mode: nil
# perl-indent-level: 2
# End:
