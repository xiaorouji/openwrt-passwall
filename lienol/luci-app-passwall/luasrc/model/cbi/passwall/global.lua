local o = require "luci.dispatcher"
local fs = require "nixio.fs"
local sys = require "luci.sys"
local ipkg = require("luci.model.ipkg")
local cursor = luci.model.uci.cursor()
local i = "passwall"
local a,t,e

local function is_installed(e)
	return ipkg.installed(e)
end

local function is_finded(e)
	return sys.exec("find /usr/*bin -iname "..e.." -type f") ~="" and true or false
end

local function has_udp_relay()
    return sys.call("lsmod | grep TPROXY >/dev/null") == 0
end

local n={}
cursor:foreach(i,"servers",function(e)
	if e.server_type and e.server and e.remarks then
		if e.use_kcp and e.use_kcp == "1" then
			n[e[".name"]]="%s+%s：[%s] %s"%{e.server_type,"Kcptun",e.remarks,e.server}
		else
			n[e[".name"]]="%s：[%s] %s"%{e.server_type,e.remarks,e.server}
		end
	end
end)

a=Map(i)
a:append(Template("passwall/global/status"))

t=a:section(TypedSection,"global",translate("Global Setting"))
t.anonymous=true
t.addremove=false

e=t:option(ListValue,"tcp_redir_server",translate("TCP Redir Server"),translate("For used to surf the Internet."))
e:value("nil",translate("Close"))
for a,t in pairs(n)do e:value(a,t)end

if has_udp_relay() then
	e=t:option(ListValue,"udp_redir_server",translate("UDP Redir Server"),translate("For Game Mode or DNS resolution and more.")..translate("The selected server will not use Kcptun."))
	e:value("nil",translate("Close"))
	e:value("default",translate("Same as the tcp redir server"))
	for a,t in pairs(n)do e:value(a,t)end
end

e=t:option(ListValue,"socks5_proxy_server",translate("Socks5 Proxy Server"),translate("The client can use the router's Socks5 proxy"))
e:value("nil",translate("Close"))
for a,t in pairs(n)do e:value(a,t)end

e=t:option(ListValue,"dns_mode",translate("DNS Forward Mode"))
e.rmempty=false
e:reset_values()--清空
if is_installed("ChinaDNS") or is_finded("chinadns") then
	e:value("chinadns","ChinaDNS")
end
if (is_installed("dns2socks") or is_finded("dns2socks")) and (is_finded("ss-local") or is_finded("ssr-local")) then
	e:value("dns2socks","dns2socks"..translate("Only SS/R servers are supported"))
end
if is_installed("pcap-dnsproxy") or is_finded("Pcap_DNSProxy") then
	e:value("Pcap_DNSProxy","Pcap_DNSProxy")
end
if is_installed("pdnsd") or is_installed("pdnsd-alt") or is_finded("pdnsd") then
	e:value("pdnsd","pdnsd")
end

e=t:option(ListValue,"up_dns_mode",translate("upstreamm DNS Server for ChinaDNS"))
e.default="OpenDNS_443"
e:depends("dns_mode","chinadns")
if is_installed("dnsproxy") or is_finded("dnsproxy") then
	e:value("dnsproxy","dnsproxy")
end
if is_installed("dns-forwarder") or is_finded("dns-forwarder") then
	e:value("dns-forwarder","dns-forwarder")
end
	e:value("OpenDNS_443","OpenDNS(443"..translate("Port")..")")
	e:value("OpenDNS_5353","OpenDNS(5353"..translate("Port")..")")

e=t:option(ListValue,"proxy_mode",translate("Default")..translate("Proxy Mode"))
e.default="gfwlist"
e.rmempty=false
e:value("disable",translate("No Proxy"))
e:value("global",translate("Global Proxy"))
e:value("gfwlist",translate("GFW List"))
e:value("chnroute",translate("China WhiteList"))
e:value("gamemode",translate("Game Mode"))
e:value("returnhome",translate("Return Home"))

e=t:option(ListValue,"localhost_proxy_mode",translate("Localhost")..translate("Proxy Mode"),translate("The server client can also use this rule to scientifically surf the Internet"))
e:value("default",translate("Default"))
--e:value("global",translate("Global Proxy").."（"..translate("Danger").."）")
e:value("gfwlist",translate("GFW List"))
--e:value("chnroute",translate("China WhiteList"))
e.default="default"
e.rmempty=false

local apply = luci.http.formvalue("cbi.apply")
if apply then
--os.execute("/etc/init.d/passwall restart")
end

return a
