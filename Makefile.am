cfgdir = $(datadir)/vyatta-cfg/templates
opdir = $(datadir)/vyatta-op/templates
share_perl5dir	  = $(datarootdir)/perl5/Vyatta/Conntrack
curverdir = $(sysconfdir)/config-migrate/current
modprobedir = /etc/modprobe.d

vprefix = /opt/vyatta
vsbindir = $(vprefix)/sbin

vsbin_PROGRAMS = src/vyatta-conntrack-logging
vyatta_conntrack_logging_SOURCES = vyatta-conntrack-logging.c

checkparamsonrebootdir = $(bindir)/sudo-users/check-params-on-reboot.d
checkparamsonreboot_SCRIPTS =
checkparamsonreboot_SCRIPTS += scripts/check-params-on-reboot.d/conntrack-hash-size

share_perl5_DATA = lib/Vyatta/Conntrack/Config.pm
share_perl5_DATA  += lib/Vyatta/Conntrack/ConntrackUtil.pm

sbin_SCRIPTS = scripts/vyatta-update-conntrack-log.pl
bin_sudo_usersdir = $(bindir)/sudo-users
bin_sudo_users_SCRIPTS = scripts/vyatta-show-conntrack.pl
bin_sudo_users_SCRIPTS += scripts/vyatta-delete-conntrack.pl
bin_sudo_users_SCRIPTS += scripts/vyatta-conntrack-timeouts.pl

curver_DATA = cfg-version/conntrack@1

modprobe_DATA  = etc/modprobe.d/vyatta_nf_conntrack.conf

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
	mkdir -p $(DESTDIR)$(opdir)
	cd templates-op; $(cpiop) $(DESTDIR)$(opdir)
