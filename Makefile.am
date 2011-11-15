cfgdir = $(datadir)/vyatta-cfg/templates
curverdir = $(sysconfdir)/config-migrate/current
modprobedir = /etc/modprobe.d
checkparamsonrebootdir = $(bindir)/sudo-users/check-params-on-reboot.d

checkparamsonreboot_SCRIPTS =
checkparamsonreboot_SCRIPTS += scripts/check-params-on-reboot.d/conntrack-hash-size

curver_DATA = cfg-version/conntrack@1

modprobe_DATA  = etc/modprobe.d/vyatta_nf_conntrack.conf

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates-cfg; $(cpiop) $(DESTDIR)$(cfgdir)
