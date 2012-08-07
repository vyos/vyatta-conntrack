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
  my ($rule, $srcrule, $dstrule, $err_str);
  my $tcp_and_udp = 0;
  # set CLI rule num as comment
  my @level_nodes = split (' ', $self->{_comment});
  $rule .= " -m comment --comment \"$level_nodes[2]-$level_nodes[4]\" ";

  if (defined($self->{_interface})) {
    $rule .= " -i $self->{_interface} ";
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
    $rule .= " -p $self->{_protocol}";
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

sub setup_base {
  my ($self, $level, $val_func, $exists_func, $addr_setup) = @_;
  my $config = new Vyatta::Config;

  $config->setLevel("$level");
  $self->{_comment} = $level;
  $self->{_rule_number} = $config->returnParent("..");
  $self->{_interface} = $config->$val_func("inbound-interface");

  $src->$addr_setup("$level source");
  $src->{_protocol} = $self->{_protocol};#needed to use address filter
  if (($src->{_protocol}) and (($src->{_protocol} ne 'tcp') or ($src->{_protocol} ne 'udp')) and (defined($src->{_port})) ) { 
    die "Error: Cannot specify port with protocol $src->{_protocol}\n"; 
  }
  $dst->$addr_setup("$level destination");
  $dst->{_protocol} = $self->{_protocol};#needed to use address filter
  if (($dst->{_protocol}) and (($dst->{_protocol} ne 'tcp') or ($dst->{_protocol} ne 'udp')) and (defined($dst->{_port})) ) { 
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
