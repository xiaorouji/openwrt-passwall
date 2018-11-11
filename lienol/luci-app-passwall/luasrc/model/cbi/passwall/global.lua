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
	local server_type
	if e.server_type == "ssr" then server_type = "SSR"
	elseif e.server_type == "ss" then server_type = "SS"
	elseif e.server_type == "v2ray" then server_type = "V2ray"
	elseif e.server_type == "brook" then server_type = "Brook"
	end
	if e.server_type and e.server and e.remarks then
		n[e[".name"]]="%s：[%s] %s"%{server_type,e.remarks,e.server}
	end
end)

a=Map(i,translate("Pass Wall"),translate("A lightweight secured SOCKS5 proxy"))
a.template="passwall/index"
a:append(Template("passwall/status"))

t=a:section(TypedSection,"global",translate("Global Setting"))
t.anonymous=true
t.addremove=false

e=t:option(ListValue,"global_server",translate("Global Server"))
e.default="nil"
e.rmempty=false
e:value("nil",translate("Disable"))
for a,t in pairs(n)do e:value(a,t)end

e=t:option(ListValue,"udp_redir_server",translate("UDP Redir Server"),translate("For Game Mode or DNS resolution and more.")..translate("The selected server will not use KCP."))
e.default="nil"
e.rmempty=false
if has_udp_relay() then
	e:value("nil",translate("Disable"))
	e:value("default",translate("Same as the master server"))
	for a,t in pairs(n)do e:value(a,t)end
else
	e:value("nil",translate("TPROXY is not found,cannot be used"))
end

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
	e:value("dns2socks","dns2socks")
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

t=a:section(TypedSection,"servers",translate("Servers List"),translate("Make sure that the KCP parameters are configured under the corresponding SS server to use the KCP fast switch.")..
"<br><font style='color:red'>"..
translate("Note: UDP cannot be forwarded after KCP is turned on.")..
"</font>")
t.anonymous=true
t.addremove=true
t.template="cbi/tblsection"
t.extedit=o.build_url("admin","vpn","passwall","serverconfig","%s")
function t.create(e,t)
	local e=TypedSection.create(e,t)
	luci.http.redirect(o.build_url("admin","vpn","passwall","serverconfig",e))
end

function t.remove(t,a)
	t.map.proceed=true
	t.map:del(a)
	luci.http.redirect(o.build_url("admin","vpn","passwall"))
end

e=t:option(DummyValue,"remarks",translate("Node Remarks"))
e.width="15%"

e=t:option(DummyValue,"server_type",translate("Server Type"))
e.width="10%"
e.cfgvalue=function(t,n)
local t=a.uci:get(i,n,"server_type")or""
local b=t
if t=="ssr" then b="SSR"
elseif t=="ss" then b="SS"
elseif t=="v2ray" then b="V2ray"
elseif t=="brook" then b="Brook"
end
return b
end

e=t:option(DummyValue,"server",translate("Server Address"))
e.width="15%"

e=t:option(DummyValue,"server_port",translate("Server Port"))
e.width="10%"

e=t:option(DummyValue,"encrypt_method",translate("Encrypt Method"))
e.width="15%"
e.cfgvalue=function(t,n)
local type=a.uci:get(i,n,"server_type") or ""
if type == "ssr" then
	return a.uci:get(i,n,"ssr_encrypt_method") or ""
elseif type == "ss" then
	return a.uci:get(i,n,"ss_encrypt_method") or ""
elseif type == "v2ray" then
	return a.uci:get(i,n,"v2ray_security") or ""
end
return "无"
end

e=t:option(Flag,"use_kcp",translate("KCPTUN Switch"))
e.width="10%"

e=t:option(DummyValue,"server",translate("Ping Latency"))
e.template="passwall/ping"
e.width="10%"

local apply = luci.http.formvalue("cbi.apply")
if apply then
--os.execute("/etc/init.d/passwall restart")
end

return a
