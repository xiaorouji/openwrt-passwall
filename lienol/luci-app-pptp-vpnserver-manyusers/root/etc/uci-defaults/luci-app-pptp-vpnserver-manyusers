#!/bin/sh

uci -q batch <<-EOF >/dev/null
	delete ucitrack.@pptpd[-1]
	add ucitrack pptpd
	set ucitrack.@pptpd[-1].init=pptpd
	commit ucitrack
EOF

rm -f /tmp/luci-indexcache
exit 0
