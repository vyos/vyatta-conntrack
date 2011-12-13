#!/usr/bin/perl

use strict;
use lib "/opt/vyatta/share/perl5";
use Vyatta::Conntrack::Config;

my $pfile = '/var/run/vyatta/connlogd.lock';
my $lfile = '/var/run/vyatta/connlogd.log';

my $config = new Vyatta::Conntrack::Config;
my $oconfig = new Vyatta::Conntrack::Config;
$config->setup();
$oconfig->setupOrig();

if (!($config->isDifferentFrom($oconfig))) {
  if ($config->isEmpty()) {
    print STDERR "Empty Configuration\n";
    exit 1;
  }
  # config not changed. do nothing.
  exit 0;
}

if ($config->isEmpty()) {
  # delete the daemon process
  Vyatta::Conntrack::Config::kill_daemon();
  # delete the .lock and .log file getting generated
  `rm -f $pfile`;
  `rm -f $lfile`; 
   exit 0;
}

my $cmd = $config->get_command();
if ($cmd) {
  # First stop the daemon and restart with config 
  Vyatta::Conntrack::Config::kill_daemon();
  `rm -f $pfile`;
  `rm -f $lfile`; 
   system("$cmd");
   if ($? >> 8) {
     print STDERR "Failed to start conntrack logging daemon";
     exit 1;
   }
}

exit 0;
