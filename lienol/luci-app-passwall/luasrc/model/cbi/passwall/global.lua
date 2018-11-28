local o=require "luci.dispatcher"
local fs=require "nixio.fs"
local sys=require "luci.sys"
local cursor=luci.model.uci.cursor()
local i="passwall"
local a,t,e

local function is_finded(e)
	return sys.exec("find /usr/*bin -iname "..e.." -type f") ~="" and true or false
end

local function is_installed(e)
	return luci.model.ipkg.installed(e)
end

local function has_udp_relay()
    return luci.sys.call("lsmod | grep TPROXY >/dev/null") == 0
end

local n={}
cursor:foreach(i,"servers",function(e)
	if e.server_type and e.server and e.remarks then
		n[e[".name"]]="%s：[%s] %s"%{e.server_type,e.remarks,e.server}
	end
end)

a=Map(i)
a:append(Template("passwall/global"))

t=a:section(TypedSection,"global",translate("Global Setting"))
t.anonymous=true
t.addremove=false

e=t:option(Flag,"tcp_redir",translate("Start the TCP redir"),translate("For used to surf the Internet."))
e.default=0
e.rmempty=false

e=t:option(Flag,"auto_switch",translate("Use Auto Switch"),translate("Please switch the configuration of the standby server to the automatic interface"))
e.default=0
e.rmempty=false
e:depends("tcp_redir",1)

e=t:option(ListValue,"tcp_redir_server",translate("TCP Redir Server"))
for a,t in pairs(n)do e:value(a,t)end
e:depends("tcp_redir",1)

e=t:option(Value,"tcp_redir_ports",translate("TCP Redir Ports"))
e.default="80,443"
e:value("1:65535",translate("All"))
e:value("80,443","80,443")
e:value("80:","80 "..translate("or more"))
e:value(":443","443 "..translate("or less"))
e:depends("tcp_redir",1)

if has_udp_relay() then
	e=t:option(Flag,"udp_redir",translate("Start the UDP redir"),translate("For Game Mode or DNS resolution and more.")..translate("The selected server will not use Kcptun."))
	e.default=0
	e.rmempty=false
end

e=t:option(ListValue,"udp_redir_server",translate("UDP Redir Server"))
e:value("default",translate("Same as the tcp redir server"))
for a,t in pairs(n)do e:value(a,t)end
e:depends("udp_redir",1)

e=t:option(Value,"udp_redir_ports",translate("UDP Redir Ports"))
e.default="1:65535"
e:value("1:65535",translate("All"))
e:value("53","53")
e:depends("udp_redir",1)

e=t:option(Flag,"socks5_proxy",translate("Start the Socks5 Proxy"),translate("The client can use the router's Socks5 proxy"))
e.default=0
e.rmempty=false

e=t:option(ListValue,"socks5_proxy_server",translate("Socks5 Proxy Server"))
for a,t in pairs(n)do e:value(a,t)end
e:depends("socks5_proxy",1)

e=t:option(ListValue,"proxy_mode",translate("Default")..translate("Proxy Mode"))
e.default="gfwlist"
e.rmempty=false
e:value("disable",translate("No Proxy"))
e:value("global",translate("Global Proxy"))
e:value("gfwlist",translate("GFW List"))
e:value("chnroute",translate("China WhiteList"))
e:value("gamemode",translate("Game Mode"))
e:value("returnhome",translate("Return Home"))

e=t:option(ListValue,"dns_mode",translate("DNS Forward Mode"))
e.rmempty=false
e:reset_values()--清空
if is_installed("cdns") or is_finded("cdns") then
	e:value("cdns","cdns")
end
if is_installed("ChinaDNS") or is_finded("chinadns") then
	e:value("chinadns","ChinaDNS")
end
if (is_installed("dns2socks") or is_finded("dns2socks")) and (is_finded("ss-local") or is_finded("ssr-local")) then
	e:value("dns2socks","dns2socks"..translate("仅支持SS/R服务器"))
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
	
e=t:option(Flag,"ssr_server_passwall",translate("SSR Client")..translate("Pass Wall"),translate("Check to make the SSR server client")..translate("Pass Wall"))
e.default="0"

local apply = luci.http.formvalue("cbi.apply")
if apply then
--os.execute("/etc/init.d/passwall restart")
end

return a
