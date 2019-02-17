local e = require"nixio.fs"
local e = require"luci.sys"
local i = luci.model.uci.cursor()
local net = require "luci.model.network".init()
local ifaces = e.net:devices()
local n = "passwall"
local a,t,e
local o = {}
local k = {}
i:foreach(n,"servers",function(e)
	if e.server and e.server_port and e.server~="127.0.0.1" then
		o[e[".name"]]="%s"%{e.server}
		k[e[".name"]]="%s"%{e.server_port}
	end
end)
a=Map("passwall")
-- [[ Haproxy Settings ]]--
t=a:section(TypedSection,"global_haproxy",translate("Admin Status"),translate("In the browser input routing IP plus port access, such as:192.168.1.1:1188").."<br><input type='button' class='cbi-button cbi-input-reload' value='"..translate("Click here to setting your Load Balancing").."' onclick=javascript:window.open('http://koolshare.cn/thread-65561-1-1.html','target'); />")
t.anonymous=true

e=t:option(Flag,"admin_enable",translate("Enable Admin Status"))
e.rmempty=false
e.default=false

e=t:option(Value,"admin_port",translate("Admin Status port setting"))
e.default="1188"
e:depends("admin_enable",1)

e=t:option(Value,"admin_user",translate("Admin Status User"))
e.default="admin"
e:depends("admin_enable",1)

e=t:option(Value,"admin_password",translate("Admin Status Password"))
e.password=true
e.default="admin"
e:depends("admin_enable",1)

e=t:option(Flag,"balancing_enable",translate("Enable or Disable Load Balancing"))
e.rmempty=false
e.default=false

e=t:option(Value,"haproxy_port",translate("Haproxy port setting"))
e.default="1181"
e:depends("balancing_enable",1)

t=a:section(TypedSection,"balancing",translate("Load Balancing Server Setting"),
translate("Add a load balancing server, note reading above requirements."))
t.template="cbi/tblsection"
t.sortable=true
t.anonymous=true
t.addremove=true
e=t:option(Value,"lbss",translate("Server Address"))
for a,t in pairs(o)do e:value(t,t)end
e.rmempty=false

e=t:option(Value,"lbort",translate("Server Port"))
for a,t in pairs(k)do e:value(t,t)end
e.rmempty=false

e=t:option(Value,"lbweight",translate("Server weight"))
e.default="5"
e.rmempty=false

e=t:option(ListValue,"export",translate("Export Of Multi WAN"))
e:value(0,translate("Auto"))
for _, iface in ipairs(ifaces) do
	if (iface:match("^pppoe*")) then
		local nets = net:get_interface(iface)
		nets = nets and nets:get_networks() or {}
		for k, v in pairs(nets) do
			nets[k] = nets[k].sid
		end
		nets = table.concat(nets, ",")
		e:value(iface, ((#nets > 0) and "%s (%s)" % {iface, nets} or iface))
	end
end
e.default=0
e.rmempty=false

e=t:option(ListValue,"backup",translate("Server Mode"))
e:value(0,translate("Primary Server"))
e:value(1,translate("Standby Server"))
e.rmempty=false
return a
