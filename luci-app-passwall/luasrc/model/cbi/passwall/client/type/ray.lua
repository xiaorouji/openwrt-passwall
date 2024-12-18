local m, s = ...

local api = require "luci.passwall.api"

if not api.finded_com("xray") then
	return
end

local appname = "passwall"
local jsonc = api.jsonc
local uci = api.uci

local type_name = "Xray"

local option_prefix = "xray_"

local function _n(name)
	return option_prefix .. name
end

local ss_method_list = {
	"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "xchacha20-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

local security_list = { "none", "auto", "aes-128-gcm", "chacha20-poly1305", "zero" }

local header_type_list = {
	"none", "srtp", "utp", "wechat-video", "dtls", "wireguard"
}

local xray_version = api.get_app_version("xray")
-- [[ Xray ]]

s.fields["type"]:value(type_name, "Xray")

o = s:option(ListValue, _n("protocol"), translate("Protocol"))
o:value("vmess", translate("Vmess"))
o:value("vless", translate("VLESS"))
o:value("http", translate("HTTP"))
o:value("socks", translate("Socks"))
o:value("shadowsocks", translate("Shadowsocks"))
o:value("trojan", translate("Trojan"))
o:value("wireguard", translate("WireGuard"))
o:value("_balancing", translate("Balancing"))
o:value("_shunt", translate("Shunt"))
o:value("_iface", translate("Custom Interface"))

o = s:option(Value, _n("iface"), translate("Interface"))
o.default = "eth1"
o:depends({ [_n("protocol")] = "_iface" })

local nodes_table = {}
local balancers_table = {}
local fallback_table = {}
local iface_table = {}
local is_balancer = nil
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = {
			id = e[".name"],
			remark = e["remark"],
			type = e["type"]
		}
	end
	if e.protocol == "_balancing" then
		balancers_table[#balancers_table + 1] = {
			id = e[".name"],
			remark = e["remark"]
		}
		if e[".name"] ~= arg[1] then
			fallback_table[#fallback_table + 1] = {
				id = e[".name"],
				remark = e["remark"],
				fallback = e["fallback_node"]
			}
		else
			is_balancer = true
		end
	end
	if e.protocol == "_iface" then
		iface_table[#iface_table + 1] = {
			id = e[".name"],
			remark = e["remark"]
		}
	end
end

local socks_list = {}
uci:foreach(appname, "socks", function(s)
	if s.enabled == "1" and s.node then
		socks_list[#socks_list + 1] = {
			id = "Socks_" .. s[".name"],
			remark = translate("Socks Config") .. " " .. string.format("[%s %s]", s.port, translate("Port"))
		}
	end
end)

-- 负载均衡列表
local o = s:option(DynamicList, _n("balancing_node"), translate("Load balancing node list"), translate("Load balancing node list, <a target='_blank' href='https://toutyrater.github.io/routing/balance2.html'>document</a>"))
o:depends({ [_n("protocol")] = "_balancing" })
for k, v in pairs(nodes_table) do o:value(v.id, v.remark) end

local o = s:option(ListValue, _n("balancingStrategy"), translate("Balancing Strategy"))
o:depends({ [_n("protocol")] = "_balancing" })
o:value("random")
o:value("roundRobin")
o:value("leastPing")
o.default = "leastPing"

-- Fallback Node
if api.compare_versions(xray_version, ">=", "1.8.10") then
	local o = s:option(ListValue, _n("fallback_node"), translate("Fallback Node"))
	if api.compare_versions(xray_version, ">=", "1.8.12") then
		o:depends({ [_n("protocol")] = "_balancing" })
	else
		o:depends({ [_n("balancingStrategy")] = "leastPing" })
	end
	local function check_fallback_chain(fb)
		for k, v in pairs(fallback_table) do
			if v.fallback == fb then
				fallback_table[k] = nil
				check_fallback_chain(v.id)
			end
		end
	end
	-- 检查fallback链，去掉会形成闭环的balancer节点
	if is_balancer then
		check_fallback_chain(arg[1])
	end
	for k, v in pairs(fallback_table) do o:value(v.id, v.remark) end
	for k, v in pairs(nodes_table) do o:value(v.id, v.remark) end
end

-- 探测地址
local ucpu = s:option(Flag, _n("useCustomProbeUrl"), translate("Use Custome Probe URL"), translate("By default the built-in probe URL will be used, enable this option to use a custom probe URL."))
ucpu:depends({ [_n("balancingStrategy")] = "leastPing" })

local pu = s:option(Value, _n("probeUrl"), translate("Probe URL"))
pu:depends({ [_n("useCustomProbeUrl")] = true })
pu:value("https://cp.cloudflare.com/", "Cloudflare")
pu:value("https://www.gstatic.com/generate_204", "Gstatic")
pu:value("https://www.google.com/generate_204", "Google")
pu:value("https://www.youtube.com/generate_204", "YouTube")
pu:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
pu:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
pu.default = "https://www.google.com/generate_204"
pu.description = translate("The URL used to detect the connection status.")

-- 探测间隔
local pi = s:option(Value, _n("probeInterval"), translate("Probe Interval"))
pi:depends({ [_n("balancingStrategy")] = "leastPing" })
pi.default = "1m"
pi.description = translate("The interval between initiating probes. Every time this time elapses, a server status check is performed on a server. The time format is numbers + units, such as '10s', '2h45m', and the supported time units are <code>ns</code>, <code>us</code>, <code>ms</code>, <code>s</code>, <code>m</code>, <code>h</code>, which correspond to nanoseconds, microseconds, milliseconds, seconds, minutes, and hours, respectively.")

if api.compare_versions(xray_version, ">=", "1.8.12") then
	ucpu:depends({ [_n("protocol")] = "_balancing" })
	pi:depends({ [_n("protocol")] = "_balancing" })
else
	ucpu:depends({ [_n("balancingStrategy")] = "leastPing" })
	pi:depends({ [_n("balancingStrategy")] = "leastPing" })
end


-- [[ 分流模块 ]]
if #nodes_table > 0 then
	o = s:option(Flag, _n("preproxy_enabled"), translate("Preproxy"))
	o:depends({ [_n("protocol")] = "_shunt" })

	o = s:option(ListValue, _n("main_node"), string.format('<a style="color:red">%s</a>', translate("Preproxy Node")), translate("Set the node to be used as a pre-proxy. Each rule (including <code>Default</code>) has a separate switch that controls whether this rule uses the pre-proxy or not."))
	o:depends({ [_n("protocol")] = "_shunt", [_n("preproxy_enabled")] = true })
	for k, v in pairs(socks_list) do
		o:value(v.id, v.remark)
	end
	for k, v in pairs(balancers_table) do
		o:value(v.id, v.remark)
	end
	for k, v in pairs(iface_table) do
		o:value(v.id, v.remark)
	end
	for k, v in pairs(nodes_table) do
		o:value(v.id, v.remark)
	end
end
uci:foreach(appname, "shunt_rules", function(e)
	if e[".name"] and e.remarks then
		o = s:option(ListValue, _n(e[".name"]), string.format('* <a href="%s" target="_blank">%s</a>', api.url("shunt_rules", e[".name"]), e.remarks))
		o:value("", translate("Close"))
		o:value("_default", translate("Default"))
		o:value("_direct", translate("Direct Connection"))
		o:value("_blackhole", translate("Blackhole"))
		o:depends({ [_n("protocol")] = "_shunt" })

		if #nodes_table > 0 then
			for k, v in pairs(socks_list) do
				o:value(v.id, v.remark)
			end
			for k, v in pairs(balancers_table) do
				o:value(v.id, v.remark)
			end
			for k, v in pairs(iface_table) do
				o:value(v.id, v.remark)
			end
			local pt = s:option(ListValue, _n(e[".name"] .. "_proxy_tag"), string.format('* <a style="color:red">%s</a>', e.remarks .. " " .. translate("Preproxy")))
			pt:value("", translate("Close"))
			pt:value("main", translate("Preproxy Node"))
			for k, v in pairs(nodes_table) do
				o:value(v.id, v.remark)
				pt:depends({ [_n("protocol")] = "_shunt", [_n("preproxy_enabled")] = true, [_n(e[".name"])] = v.id })
			end
		end
	end
end)

o = s:option(DummyValue, _n("shunt_tips"), " ")
o.not_rewrite = true
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<a style="color: red" href="../rule">%s</a>', translate("No shunt rules? Click me to go to add."))
end
o:depends({ [_n("protocol")] = "_shunt" })

local o = s:option(ListValue, _n("default_node"), string.format('* <a style="color:red">%s</a>', translate("Default")))
o:depends({ [_n("protocol")] = "_shunt" })
o:value("_direct", translate("Direct Connection"))
o:value("_blackhole", translate("Blackhole"))

if #nodes_table > 0 then
	for k, v in pairs(socks_list) do
		o:value(v.id, v.remark)
	end
	for k, v in pairs(balancers_table) do
		o:value(v.id, v.remark)
	end
	for k, v in pairs(iface_table) do
		o:value(v.id, v.remark)
	end
	local dpt = s:option(ListValue, _n("default_proxy_tag"), string.format('* <a style="color:red">%s</a>', translate("Default Preproxy")), translate("When using, localhost will connect this node first and then use this node to connect the default node."))
	dpt:value("", translate("Close"))
	dpt:value("main", translate("Preproxy Node"))
	for k, v in pairs(nodes_table) do
		o:value(v.id, v.remark)
		dpt:depends({ [_n("protocol")] = "_shunt", [_n("preproxy_enabled")] = true, [_n("default_node")] = v.id })
	end
end

o = s:option(ListValue, _n("domainStrategy"), translate("Domain Strategy"))
o:value("AsIs")
o:value("IPIfNonMatch")
o:value("IPOnDemand")
o.default = "IPOnDemand"
o.description = "<br /><ul><li>" .. translate("'AsIs': Only use domain for routing. Default value.")
	.. "</li><li>" .. translate("'IPIfNonMatch': When no rule matches current domain, resolves it into IP addresses (A or AAAA records) and try all rules again.")
	.. "</li><li>" .. translate("'IPOnDemand': As long as there is a IP-based rule, resolves the domain into IP immediately.")
	.. "</li></ul>"
o:depends({ [_n("protocol")] = "_shunt" })

o = s:option(ListValue, _n("domainMatcher"), translate("Domain matcher"))
o:value("hybrid")
o:value("linear")
o:depends({ [_n("protocol")] = "_shunt" })

-- [[ 分流模块 End ]]

o = s:option(Value, _n("address"), translate("Address (Support Domain Name)"))

o = s:option(Value, _n("port"), translate("Port"))
o.datatype = "port"

local protocols = s.fields[_n("protocol")].keylist
if #protocols > 0 then
	for index, value in ipairs(protocols) do
		if not value:find("_") then
			s.fields[_n("address")]:depends({ [_n("protocol")] = value })
			s.fields[_n("port")]:depends({ [_n("protocol")] = value })
		end
	end
end

o = s:option(Value, _n("username"), translate("Username"))
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })

o = s:option(Value, _n("password"), translate("Password"))
o.password = true
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

o = s:option(ListValue, _n("security"), translate("Encrypt Method"))
for a, t in ipairs(security_list) do o:value(t) end
o:depends({ [_n("protocol")] = "vmess" })

o = s:option(Value, _n("encryption"), translate("Encrypt Method"))
o.default = "none"
o:value("none")
o:depends({ [_n("protocol")] = "vless" })

o = s:option(ListValue, _n("ss_method"), translate("Encrypt Method"))
o.rewrite_option = "method"
for a, t in ipairs(ss_method_list) do o:value(t) end
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Flag, _n("iv_check"), translate("IV Check"))
o:depends({ [_n("protocol")] = "shadowsocks", [_n("ss_method")] = "aes-128-gcm" })
o:depends({ [_n("protocol")] = "shadowsocks", [_n("ss_method")] = "aes-256-gcm" })
o:depends({ [_n("protocol")] = "shadowsocks", [_n("ss_method")] = "chacha20-poly1305" })
o:depends({ [_n("protocol")] = "shadowsocks", [_n("ss_method")] = "xchacha20-poly1305" })

o = s:option(Flag, _n("uot"), translate("UDP over TCP"))
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Value, _n("uuid"), translate("ID"))
o.password = true
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })

o = s:option(ListValue, _n("flow"), translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:depends({ [_n("protocol")] = "vless", [_n("tls")] = true, [_n("transport")] = "raw" })

o = s:option(Flag, _n("tls"), translate("TLS"))
o.default = 0
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Flag, _n("reality"), translate("REALITY"), translate("Only recommend to use with VLESS-TCP-XTLS-Vision."))
o.default = 0
o:depends({ [_n("tls")] = true, [_n("transport")] = "raw" })
o:depends({ [_n("tls")] = true, [_n("transport")] = "h2" })
o:depends({ [_n("tls")] = true, [_n("transport")] = "grpc" })
o:depends({ [_n("tls")] = true, [_n("transport")] = "xhttp" })

o = s:option(ListValue, _n("alpn"), translate("alpn"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends({ [_n("tls")] = true, [_n("reality")] = false })

-- o = s:option(Value, _n("minversion"), translate("minversion"))
-- o.default = "1.3"
-- o:value("1.3")
-- o:depends({ [_n("tls")] = true })

o = s:option(Value, _n("tls_serverName"), translate("Domain"))
o:depends({ [_n("tls")] = true })

o = s:option(Flag, _n("tls_allowInsecure"), translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"
o:depends({ [_n("tls")] = true, [_n("reality")] = false })

-- [[ REALITY部分 ]] --
o = s:option(Value, _n("reality_publicKey"), translate("Public Key"))
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Value, _n("reality_shortId"), translate("Short Id"))
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Value, _n("reality_spiderX"), translate("Spider X"))
o.placeholder = "/"
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(Flag, _n("utls"), translate("uTLS"))
o.default = "0"
o:depends({ [_n("tls")] = true, [_n("reality")] = false })

o = s:option(ListValue, _n("fingerprint"), translate("Finger Print"))
o:value("chrome")
o:value("firefox")
o:value("edge")
o:value("safari")
o:value("360")
o:value("qq")
o:value("ios")
o:value("android")
o:value("random")
o:value("randomized")
o.default = "chrome"
o:depends({ [_n("tls")] = true, [_n("utls")] = true })
o:depends({ [_n("tls")] = true, [_n("reality")] = true })

o = s:option(ListValue, _n("transport"), translate("Transport"))
o:value("raw", "RAW (TCP)")
o:value("mkcp", "mKCP")
o:value("ws", "WebSocket")
o:value("h2", "HTTP/2")
o:value("ds", "DomainSocket")
o:value("quic", "QUIC")
o:value("grpc", "gRPC")
o:value("httpupgrade", "HttpUpgrade")
o:value("xhttp", "XHTTP (SplitHTTP)")
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

o = s:option(Value, _n("wireguard_public_key"), translate("Public Key"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(Value, _n("wireguard_secret_key"), translate("Private Key"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(Value, _n("wireguard_preSharedKey"), translate("Pre shared key"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(DynamicList, _n("wireguard_local_address"), translate("Local Address"))
o:depends({ [_n("protocol")] = "wireguard" })

o = s:option(Value, _n("wireguard_mtu"), translate("MTU"))
o.default = "1420"
o:depends({ [_n("protocol")] = "wireguard" })

if api.compare_versions(xray_version, ">=", "1.8.0") then
	o = s:option(Value, _n("wireguard_reserved"), translate("Reserved"), translate("Decimal numbers separated by \",\" or Base64-encoded strings."))
	o:depends({ [_n("protocol")] = "wireguard" })
end

o = s:option(Value, _n("wireguard_keepAlive"), translate("Keep Alive"))
o.default = "0"
o:depends({ [_n("protocol")] = "wireguard" })

-- [[ RAW部分 ]]--

-- TCP伪装
o = s:option(ListValue, _n("tcp_guise"), translate("Camouflage Type"))
o:value("none", "none")
o:value("http", "http")
o:depends({ [_n("transport")] = "raw" })

-- HTTP域名
o = s:option(DynamicList, _n("tcp_guise_http_host"), translate("HTTP Host"))
o:depends({ [_n("tcp_guise")] = "http" })

-- HTTP路径
o = s:option(DynamicList, _n("tcp_guise_http_path"), translate("HTTP Path"))
o.placeholder = "/"
o:depends({ [_n("tcp_guise")] = "http" })

-- [[ mKCP部分 ]]--

o = s:option(ListValue, _n("mkcp_guise"), translate("Camouflage Type"), translate('<br />none: default, no masquerade, data sent is packets with no characteristics.<br />srtp: disguised as an SRTP packet, it will be recognized as video call data (such as FaceTime).<br />utp: packets disguised as uTP will be recognized as bittorrent downloaded data.<br />wechat-video: packets disguised as WeChat video calls.<br />dtls: disguised as DTLS 1.2 packet.<br />wireguard: disguised as a WireGuard packet. (not really WireGuard protocol)'))
for a, t in ipairs(header_type_list) do o:value(t) end
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_mtu"), translate("KCP MTU"))
o.default = "1350"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_tti"), translate("KCP TTI"))
o.default = "20"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_uplinkCapacity"), translate("KCP uplinkCapacity"))
o.default = "5"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_downlinkCapacity"), translate("KCP downlinkCapacity"))
o.default = "20"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Flag, _n("mkcp_congestion"), translate("KCP Congestion"))
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_readBufferSize"), translate("KCP readBufferSize"))
o.default = "1"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_writeBufferSize"), translate("KCP writeBufferSize"))
o.default = "1"
o:depends({ [_n("transport")] = "mkcp" })

o = s:option(Value, _n("mkcp_seed"), translate("KCP Seed"))
o:depends({ [_n("transport")] = "mkcp" })

-- [[ WebSocket部分 ]]--
o = s:option(Value, _n("ws_host"), translate("WebSocket Host"))
o:depends({ [_n("transport")] = "ws" })

o = s:option(Value, _n("ws_path"), translate("WebSocket Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "ws" })

o = s:option(Value, _n("ws_heartbeatPeriod"), translate("HeartbeatPeriod(second)"))
o.datatype = "integer"
o:depends({ [_n("transport")] = "ws" })

-- [[ HTTP/2部分 ]]--
o = s:option(Value, _n("h2_host"), translate("HTTP/2 Host"))
o:depends({ [_n("transport")] = "h2" })

o = s:option(Value, _n("h2_path"), translate("HTTP/2 Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "h2" })

o = s:option(Flag, _n("h2_health_check"), translate("Health check"))
o:depends({ [_n("transport")] = "h2" })

o = s:option(Value, _n("h2_read_idle_timeout"), translate("Idle timeout"))
o.default = "10"
o:depends({ [_n("h2_health_check")] = true })

o = s:option(Value, _n("h2_health_check_timeout"), translate("Health check timeout"))
o.default = "15"
o:depends({ [_n("h2_health_check")] = true })

-- [[ DomainSocket部分 ]]--
o = s:option(Value, _n("ds_path"), "Path", translate("A legal file path. This file must not exist before running."))
o:depends({ [_n("transport")] = "ds" })

-- [[ QUIC部分 ]]--
o = s:option(ListValue, _n("quic_security"), translate("Encrypt Method"))
o:value("none")
o:value("aes-128-gcm")
o:value("chacha20-poly1305")
o:depends({ [_n("transport")] = "quic" })

o = s:option(Value, _n("quic_key"), translate("Encrypt Method") .. translate("Key"))
o:depends({ [_n("transport")] = "quic" })

o = s:option(ListValue, _n("quic_guise"), translate("Camouflage Type"))
for a, t in ipairs(header_type_list) do o:value(t) end
o:depends({ [_n("transport")] = "quic" })

-- [[ gRPC部分 ]]--
o = s:option(Value, _n("grpc_serviceName"), "ServiceName")
o:depends({ [_n("transport")] = "grpc" })

o = s:option(ListValue, _n("grpc_mode"), "gRPC " .. translate("Transfer mode"))
o:value("gun")
o:value("multi")
o:depends({ [_n("transport")] = "grpc" })

o = s:option(Flag, _n("grpc_health_check"), translate("Health check"))
o:depends({ [_n("transport")] = "grpc" })

o = s:option(Value, _n("grpc_idle_timeout"), translate("Idle timeout"))
o.default = "10"
o:depends({ [_n("grpc_health_check")] = true })

o = s:option(Value, _n("grpc_health_check_timeout"), translate("Health check timeout"))
o.default = "20"
o:depends({ [_n("grpc_health_check")] = true })

o = s:option(Flag, _n("grpc_permit_without_stream"), translate("Permit without stream"))
o.default = "0"
o:depends({ [_n("grpc_health_check")] = true })

o = s:option(Value, _n("grpc_initial_windows_size"), translate("Initial Windows Size"))
o.default = "0"
o:depends({ [_n("transport")] = "grpc" })

-- [[ HttpUpgrade部分 ]]--
o = s:option(Value, _n("httpupgrade_host"), translate("HttpUpgrade Host"))
o:depends({ [_n("transport")] = "httpupgrade" })

o = s:option(Value, _n("httpupgrade_path"), translate("HttpUpgrade Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "httpupgrade" })

-- [[ XHTTP部分 ]]--
o = s:option(ListValue, _n("xhttp_mode"), "XHTTP " .. translate("Mode"))
o:depends({ [_n("transport")] = "xhttp" })
o.default = "auto"
o:value("auto")
o:value("packet-up")
o:value("stream-up")
o:value("stream-one")

o = s:option(Value, _n("xhttp_host"), translate("XHTTP Host"))
o:depends({ [_n("transport")] = "xhttp" })

o = s:option(Value, _n("xhttp_path"), translate("XHTTP Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "xhttp" })

o = s:option(TextValue, _n("xhttp_extra"), translate("XHTTP Extra"), translate("An <a target='_blank' href='https://xtls.github.io/config/transports/splithttp.html#extra'>XHTTP extra object</a> in raw json"))
o:depends({ [_n("transport")] = "xhttp" })
o.rows = 15
o.wrap = "off"
o.custom_write = function(self, section, value)

	m:set(section, self.option:sub(1 + #option_prefix), value)

	local success, data = pcall(jsonc.parse, value)
	if success and data then
		local address = (data.extra and data.extra.downloadSettings and data.extra.downloadSettings.address)
			or (data.downloadSettings and data.downloadSettings.address)
		if address and address ~= "" then
			m:set(section, "download_address", address)
		else
			m:del(section, "download_address")
		end
	else
		m:del(section, "download_address")
	end
end
o.validate = function(self, value)
	value = value:gsub("\r\n", "\n"):gsub("^[ \t]*\n", ""):gsub("\n[ \t]*$", ""):gsub("\n[ \t]*\n", "\n")
	if value:sub(-1) == "\n" then
		value = value:sub(1, -2)
	end
	return value
end

-- [[ Mux.Cool ]]--
o = s:option(Flag, _n("mux"), "Mux", translate("Enable Mux.Cool"))
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless", [_n("flow")] = "" })
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

o = s:option(Value, _n("mux_concurrency"), translate("Mux concurrency"))
o.default = 8
o:depends({ [_n("mux")] = true })

-- [[ XUDP Mux ]]--
o = s:option(Flag, _n("xmux"), "XUDP Mux")
o.default = 1
o:depends({ [_n("protocol")] = "vless", [_n("flow")] = "xtls-rprx-vision" })

o = s:option(Value, _n("xudp_concurrency"), translate("XUDP Mux concurrency"))
o.default = 8
o:depends({ [_n("xmux")] = true })

--[[tcpMptcp]]
o = s:option(Flag, _n("tcpMptcp"), "tcpMptcp", translate("Enable Multipath TCP, need to be enabled in both server and client configuration."))
o.default = 0

o = s:option(Flag, _n("tcpNoDelay"), "tcpNoDelay")
o.default = 0

o = s:option(ListValue, _n("chain_proxy"), translate("Chain Proxy"))
o:value("", translate("Close(Not use)"))
o:value("1", translate("Preproxy Node"))
o:value("2", translate("Landing Node"))
for i, v in ipairs(s.fields[_n("protocol")].keylist) do
	if not v:find("_") then
		o:depends({ [_n("protocol")] = v })
	end
end

o = s:option(ListValue, _n("preproxy_node"), translate("Preproxy Node"), translate("Only support a layer of proxy."))
o:depends({ [_n("chain_proxy")] = "1" })

o = s:option(ListValue, _n("to_node"), translate("Landing Node"), translate("Only support a layer of proxy."))
o:depends({ [_n("chain_proxy")] = "2" })

for k, v in pairs(nodes_table) do
	if v.type == "Xray" and v.id ~= arg[1] then
		s.fields[_n("preproxy_node")]:value(v.id, v.remark)
		s.fields[_n("to_node")]:value(v.id, v.remark)
	end
end

for i, v in ipairs(s.fields[_n("protocol")].keylist) do
	if not v:find("_") then
		s.fields[_n("tcpMptcp")]:depends({ [_n("protocol")] = v })
		s.fields[_n("tcpNoDelay")]:depends({ [_n("protocol")] = v })
		s.fields[_n("chain_proxy")]:depends({ [_n("protocol")] = v })
	end
end

api.luci_types(arg[1], m, s, type_name, option_prefix)
