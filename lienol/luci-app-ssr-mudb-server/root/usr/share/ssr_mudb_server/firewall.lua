#!/usr/bin/lua

require 'luci.sys'
local luci = luci
local jsonc = require "luci.jsonc"

local json = jsonc.parse(luci.sys.exec("cat /usr/share/ssr_mudb_server/mudb.json"))
if json then
	for index = 1, table.maxn(json) do
		local o = json[index]
		if o.enable == 1 then
			luci.sys.call(string.format("iptables -A SSR_MUDB-SERVER -p tcp --dport %s -m comment --comment %s -j ACCEPT", o.port, o.user))
			luci.sys.call(string.format("iptables -A SSR_MUDB-SERVER -p udp --dport %s -m comment --comment %s -j ACCEPT", o.port, o.user))
		end
	end
end