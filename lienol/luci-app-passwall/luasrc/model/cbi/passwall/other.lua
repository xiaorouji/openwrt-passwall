local fs = require"nixio.fs"
local net = require "luci.model.network".init()
local ifaces = require "luci.sys".net:devices()
m=Map("passwall")

-- [[ Delay Settings ]]--
s=m:section(TypedSection,"global_delay",translate("Start Delay"))
s.anonymous=true
s.addremove=false

o=s:option(Value,"start_delay",translate("Delay Start"),translate("Units:seconds"))
o.default="0"
o.rmempty=true

o=s:option(Flag,"disconnect_reconnect_on",translate("Disconnection auto reconnection"))
o.default=0
o.rmempty=false

o=s:option(Value,"disconnect_reconnect_time",translate("How often is a diagnosis made"),translate("Units:minutes"))
o:depends("disconnect_reconnect_on","1")
o.default="10"
o.rmempty=true

o=s:option(Flag,"auto_on",translate("Open and close automatically"))
o.default=0
o.rmempty=false

o=s:option(ListValue,"time_off",translate("Automatically turn off time"))
o:depends("auto_on","1")
o:value(nil,translate("Disable"))
for e=0,23 do
o:value(e,e..translate("oclock"))
end
o.default=nil

o=s:option(ListValue,"time_on",translate("Automatically turn on time"))
o:depends("auto_on","1")
o:value(nil,translate("Disable"))
for e=0,23 do
o:value(e,e..translate("oclock"))
end
o.default=nil

o=s:option(ListValue,"time_restart",translate("Automatically restart time"))
o:depends("auto_on","1")
o:value(nil,translate("Disable"))
for e=0,23 do
o:value(e,e..translate("oclock"))
end
o.default=nil

-- [[ DNS Settings ]]--
s=m:section(TypedSection,"global_dns",translate("DNS Setting"))
s.anonymous=true
s.addremove=false
o=s:option(Value,"dns_forward",translate("DNS Forward Address"))
o.default="8.8.8.8:53"
o:value("8.8.8.8:53","8.8.8.8:53(Google DNS1)")
o:value("8.8.4.4:53","8.8.4.4:53(Google DNS2)")
o:value("208.67.222.222:53","208.67.222.222:53(OpenDNS DNS1_53)")
o:value("208.67.222.222:5353","208.67.222.222:5353(OpenDNS DNS1_5353)")
o:value("208.67.222.222:443","208.67.222.222:443(OpenDNS DNS1_443)")
o:value("208.67.220.220:53","208.67.222.220:53(OpenDNS DNS2_53)")
o:value("208.67.220.220:5353","208.67.222.220:5353(OpenDNS DNS2_5353)")
o:value("208.67.220.220:443","208.67.222.220:443(OpenDNS DNS2_443)")
o.rmempty=false
o=s:option(Value,"dns_1",translate("Mainland DNS Sever 1"))
o.default="dnsbyisp"
o:value("dnsbyisp",translate("dnsbyisp"))
o:value("223.5.5.5","223.5.5.5("..translate("Ali").."DNS1)")
o:value("223.6.6.6","223.6.6.6("..translate("Ali").."DNS2)")
o:value("114.114.114.114","114.114.114.114(114DNS1)")
o:value("114.114.115.115","114.114.115.115(114DNS2)")
o:value("119.29.29.29","119.29.29.29(DNSPOD DNS1)")
o:value("182.254.116.116","182.254.116.116(DNSPOD DNS2)")
o:value("1.2.4.8","1.2.4.8(CNNIC DNS1)")
o:value("210.2.4.8","210.2.4.8(CNNIC DNS2)")
o:value("180.76.76.76","180.76.76.76("..translate("Baidu").."DNS)")
o.rmempty=false
o=s:option(Value,"dns_2",translate("Mainland DNS Sever 2"))
o.default="223.5.5.5"
o:value("dnsbyisp",translate("dnsbyisp"))
o:value("223.5.5.5","223.5.5.5("..translate("Ali").."DNS1)")
o:value("223.6.6.6","223.6.6.6("..translate("Ali").."DNS2)")
o:value("114.114.114.114","114.114.114.114(114DNS1)")
o:value("114.114.115.115","114.114.115.115(114DNS2)")
o:value("119.29.29.29","119.29.29.29(DNSPOD DNS1)")
o:value("182.254.116.116","182.254.116.116(DNSPOD DNS2)")
o:value("1.2.4.8","1.2.4.8(CNNIC DNS1)")
o:value("210.2.4.8","210.2.4.8(CNNIC DNS2)")
o:value("180.76.76.76","180.76.76.76("..translate("Baidu").."DNS)")
o.rmempty=false

o=s:option(ListValue,"dns_port",translate("DNS Export Of Multi WAN"))
o:value(0,translate("None specify"))
for _, iface in ipairs(ifaces) do
	if (iface:match("^br*") or iface:match("^eth*") or iface:match("^pppoe*") or iface:match("wlan*")) then
		local nets = net:get_interface(iface)
		nets = nets and nets:get_networks() or {}
		for k, v in pairs(nets) do
			nets[k] = nets[k].sid
		end
		nets = table.concat(nets, ",")
		o:value(iface, ((#nets > 0) and "%s (%s)" % {iface, nets} or iface))
	end
end
o.default=0
o.rmempty=false

o=s:option(ListValue,"wan_port",translate("Designated Export for SS"))
o:value(0,translate("None specify"))
for _, iface in ipairs(ifaces) do
	if (iface:match("^br*") or iface:match("^eth*") or iface:match("^pppoe*") or iface:match("wlan*")) then
		local nets = net:get_interface(iface)
		nets = nets and nets:get_networks() or {}
		for k, v in pairs(nets) do
			nets[k] = nets[k].sid
		end
		nets = table.concat(nets, ",")
		o:value(iface, ((#nets > 0) and "%s (%s)" % {iface, nets} or iface))
	end
end
o.default=0
o.rmempty=false

o=s:option(Flag,"dns_53",translate("DNS Hijack"))
o.default=0
o.rmempty=false

-- [[ Proxy Settings ]]--
s=m:section(TypedSection,"global_proxy",translate("Proxy Settings"))
s.anonymous=true
s.addremove=false

o=s:option(Value,"tcp_redir_port",translate("TCP Redir Port"))
o.datatype="port"
o.default=1031
o.rmempty=true

o=s:option(Value,"udp_redir_port",translate("UDP Redir Port"))
o.datatype="port"
o.default=1032
o.rmempty=true

o=s:option(Value,"socks5_port",translate("Socks5 Proxy Port"))
o.datatype="port"
o.default=1033

o=s:option(Value,"kcptun_port",translate("Kcptun Port"))
o.datatype="port"
o.default=11183
o.rmempty=true

o=s:option(Flag,"proxy_ipv6",translate("Proxy IPv6"),translate("The IPv6 traffic can be proxyed when selected"))
o.default=0

-- [[ Custom Dnsmasq Settings ]]--
s=m:section(TypedSection,"global",translate("Custom Dnsmasq"))
s.anonymous=true
local e="/usr/share/passwall/dnsmasq.d/user.conf"
o=s:option(TextValue,"userconf")
o.description=translate("Setting a parameter error will cause dnsmasq fail to start.")
o.rows=15
o.wrap="off"
o.cfgvalue=function(a,a)
return fs.readfile(e)or""
end
o.write=function(o,o,a)
fs.writefile(e,a:gsub("\r\n","\n"))
end
return m
