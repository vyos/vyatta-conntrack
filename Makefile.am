cfgdir = $(datadir)/vyatta-cfg/templates
curverdir = $(sysconfdir)/config-migrate/current

curver_DATA = cfg-version/conntrack@1

cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

install-exec-hook:
	mkdir -p $(DESTDIR)$(cfgdir)
	cd templates; $(cpiop) $(DESTDIR)$(cfgdir)
