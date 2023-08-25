local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("xray") and not api.is_finded("v2ray") then
	return
end

local appname = api.appname
local uci = api.uci

local option_prefix = "xray_"

local function option_name(name)
	return option_prefix .. name
end

local function rm_prefix_cfgvalue(self, section)
	if self.option:find(option_prefix) == 1 then
		return m:get(section, self.option:sub(1 + #option_prefix))
	end
end
local function rm_prefix_write(self, section, value)
	if self.option:find(option_prefix) == 1 then
		m:set(section, self.option:sub(1 + #option_prefix), value)
	end
end
local function rm_prefix_remove(self, section, value)
	if self.option:find(option_prefix) == 1 then
		m:del(section, self.option:sub(1 + #option_prefix))
	end
end

local function add_xray_depends(o, field, value)
	local deps = { type = "Xray" }
	if field then
		if type(field) == "string" then
			deps[field] = value
		else
			for key, value in pairs(field) do
				deps[key] = value
			end
		end
	end
	o:depends(deps)
end

local function add_v2ray_depends(o, field, value)
	local deps = { type = "V2ray" }
	if field then
		if type(field) == "string" then
			deps[field] = value
		else
			for key, value in pairs(field) do
				deps[key] = value
			end
		end
	end
	o:depends(deps)
end

local v_ss_encrypt_method_list = {
	"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"
}

local x_ss_encrypt_method_list = {
	"aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "xchacha20-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

local security_list = { "none", "auto", "aes-128-gcm", "chacha20-poly1305", "zero" }

local header_type_list = {
	"none", "srtp", "utp", "wechat-video", "dtls", "wireguard"
}

-- [[ Xray ]]

if api.is_finded("xray") then
	s.fields["type"]:value("Xray", translate("Xray"))
end
if api.is_finded("v2ray") then
	s.fields["type"]:value("V2ray", translate("V2ray"))
end

o = s:option(ListValue, "xray_protocol", translate("Protocol"))
o:value("vmess", translate("Vmess"))
o:value("vless", translate("VLESS"))
o:value("http", translate("HTTP"))
o:value("socks", translate("Socks"))
o:value("shadowsocks", translate("Shadowsocks"))
o:value("trojan", translate("Trojan"))
o:value("wireguard", translate("WireGuard"))
o:value("_balancing", translate("Balancing"))
o:value("_shunt", translate("Shunt"))
o:value("_iface", translate("Custom Interface") .. " (Only Support Xray)")
add_xray_depends(o)
add_v2ray_depends(o)
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(Value, "xray_iface", translate("Interface"))
o.default = "eth1"
add_xray_depends(o, { xray_protocol = "_iface" })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

local nodes_table = {}
local balancers_table = {}
local iface_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = {
			id = e[".name"],
			remarks = e["remark"]
		}
	end
	if e.protocol == "_balancing" then
		balancers_table[#balancers_table + 1] = {
			id = e[".name"],
			remarks = e["remark"]
		}
	end
	if e.protocol == "_iface" then
		iface_table[#iface_table + 1] = {
			id = e[".name"],
			remarks = e["remark"]
		}
	end
end

-- 负载均衡列表
local o = s:option(DynamicList, "xray_balancing_node", translate("Load balancing node list"), translate("Load balancing node list, <a target='_blank' href='https://toutyrater.github.io/routing/balance2.html'>document</a>"))
add_xray_depends(o, { xray_protocol = "_balancing" })
add_v2ray_depends(o, { xray_protocol = "_balancing" })
for k, v in pairs(nodes_table) do o:value(v.id, v.remarks) end
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

local o = s:option(ListValue, "xray_balancingStrategy", translate("Balancing Strategy"))
add_xray_depends(o, { xray_protocol = "_balancing" })
add_v2ray_depends(o, { xray_protocol = "_balancing" })
o:value("random")
o:value("leastPing")
o.default = "random"
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

-- 探测地址
local o = s:option(Flag, "xray_useCustomProbeUrl", translate("Use Custome Probe URL"), translate("By default the built-in probe URL will be used, enable this option to use a custom probe URL."))
add_xray_depends(o, { xray_balancingStrategy = "leastPing" })
add_v2ray_depends(o, { xray_balancingStrategy = "leastPing" })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

local o = s:option(Value, "xray_probeUrl", translate("Probe URL"))
add_xray_depends(o, { xray_useCustomProbeUrl = true })
add_v2ray_depends(o, { xray_useCustomProbeUrl = true })
o.default = "https://www.google.com/generate_204"
o.description = translate("The URL used to detect the connection status.")
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

-- 探测间隔
local o = s:option(Value, "xray_probeInterval", translate("Probe Interval"))
add_xray_depends(o, { xray_balancingStrategy = "leastPing" })
add_v2ray_depends(o, { xray_balancingStrategy = "leastPing" })
o.default = "1m"
o.description = translate("The interval between initiating probes. Every time this time elapses, a server status check is performed on a server. The time format is numbers + units, such as '10s', '2h45m', and the supported time units are <code>ns</code>, <code>us</code>, <code>ms</code>, <code>s</code>, <code>m</code>, <code>h</code>, which correspond to nanoseconds, microseconds, milliseconds, seconds, minutes, and hours, respectively.")
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

-- [[ 分流模块 ]]
if #nodes_table > 0 then
	o = s:option(Flag, "preproxy_enabled", translate("Preproxy"))
	add_xray_depends(o, { xray_protocol = "_shunt" })
	add_v2ray_depends(o, { xray_protocol = "_shunt" })
	o = s:option(Value, "main_node", string.format('<a style="color:red">%s</a>', translate("Preproxy Node")), translate("Set the node to be used as a pre-proxy. Each rule (including <code>Default</code>) has a separate switch that controls whether this rule uses the pre-proxy or not."))
	add_xray_depends(o, { xray_protocol = "_shunt", preproxy_enabled = true })
	add_v2ray_depends(o, { xray_protocol = "_shunt", preproxy_enabled = true })
	for k, v in pairs(balancers_table) do
		o:value(v.id, v.remarks)
	end
	for k, v in pairs(iface_table) do
		o:value(v.id, v.remarks)
	end
	for k, v in pairs(nodes_table) do
		o:value(v.id, v.remarks)
	end
	o.default = "nil"
end
uci:foreach(appname, "shunt_rules", function(e)
	if e[".name"] and e.remarks then
		o = s:option(Value, e[".name"], string.format('* <a href="%s" target="_blank">%s</a>', api.url("shunt_rules", e[".name"]), e.remarks))
		o:value("nil", translate("Close"))
		o:value("_default", translate("Default"))
		o:value("_direct", translate("Direct Connection"))
		o:value("_blackhole", translate("Blackhole"))
		add_xray_depends(o, { xray_protocol = "_shunt" })
		add_v2ray_depends(o, { xray_protocol = "_shunt" })

		if #nodes_table > 0 then
			for k, v in pairs(balancers_table) do
				o:value(v.id, v.remarks)
			end
			for k, v in pairs(iface_table) do
				o:value(v.id, v.remarks)
			end
			local pt = s:option(ListValue, e[".name"] .. "_proxy_tag", string.format('* <a style="color:red">%s</a>', e.remarks .. " " .. translate("Preproxy")))
			pt:value("nil", translate("Close"))
			pt:value("main", translate("Preproxy Node"))
			pt.default = "nil"
			for k, v in pairs(nodes_table) do
				o:value(v.id, v.remarks)
				add_xray_depends(pt, { xray_protocol = "_shunt", preproxy_enabled = "1", [e[".name"]] = v.id })
				add_v2ray_depends(pt, { xray_protocol = "_shunt", preproxy_enabled = "1", [e[".name"]] = v.id })
			end
		end
	end
end)

o = s:option(DummyValue, "shunt_tips", " ")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<a style="color: red" href="../rule">%s</a>', translate("No shunt rules? Click me to go to add."))
end
add_xray_depends(o, { xray_protocol = "_shunt" })

local o = s:option(Value, "default_node", string.format('* <a style="color:red">%s</a>', translate("Default")))
add_xray_depends(o, { xray_protocol = "_shunt" })
o:value("_direct", translate("Direct Connection"))
o:value("_blackhole", translate("Blackhole"))

if #nodes_table > 0 then
	for k, v in pairs(balancers_table) do
		o:value(v.id, v.remarks)
	end
	for k, v in pairs(iface_table) do
		o:value(v.id, v.remarks)
	end
	local dpt = s:option(ListValue, "default_proxy_tag", string.format('* <a style="color:red">%s</a>', translate("Default Preproxy")), translate("When using, localhost will connect this node first and then use this node to connect the default node."))
	dpt:value("nil", translate("Close"))
	dpt:value("main", translate("Preproxy Node"))
	dpt.default = "nil"
	for k, v in pairs(nodes_table) do
		o:value(v.id, v.remarks)
		add_xray_depends(dpt, { xray_protocol = "_shunt", preproxy_enabled = "1", default_node = v.id })
	end
end

o = s:option(ListValue, "domainStrategy", translate("Domain Strategy"))
o:value("AsIs")
o:value("IPIfNonMatch")
o:value("IPOnDemand")
o.default = "IPOnDemand"
o.description = "<br /><ul><li>" .. translate("'AsIs': Only use domain for routing. Default value.")
	.. "</li><li>" .. translate("'IPIfNonMatch': When no rule matches current domain, resolves it into IP addresses (A or AAAA records) and try all rules again.")
	.. "</li><li>" .. translate("'IPOnDemand': As long as there is a IP-based rule, resolves the domain into IP immediately.")
	.. "</li></ul>"
add_xray_depends(o, { xray_protocol = "_shunt" })

o = s:option(ListValue, "domainMatcher", translate("Domain matcher"))
o:value("hybrid")
o:value("linear")
add_xray_depends(o, { xray_protocol = "_shunt" })

-- [[ 分流模块 End ]]

o = s:option(Value, "xray_address", translate("Address (Support Domain Name)"))
add_xray_depends(o, { xray_protocol = "vmess" })
add_xray_depends(o, { xray_protocol = "vless" })
add_xray_depends(o, { xray_protocol = "http" })
add_xray_depends(o, { xray_protocol = "socks" })
add_xray_depends(o, { xray_protocol = "shadowsocks" })
add_xray_depends(o, { xray_protocol = "trojan" })
add_xray_depends(o, { xray_protocol = "wireguard" })
add_v2ray_depends(o, { xray_protocol = "vmess" })
add_v2ray_depends(o, { xray_protocol = "vless" })
add_v2ray_depends(o, { xray_protocol = "http" })
add_v2ray_depends(o, { xray_protocol = "socks" })
add_v2ray_depends(o, { xray_protocol = "shadowsocks" })
add_v2ray_depends(o, { xray_protocol = "trojan" })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(Value, "xray_port", translate("Port"))
o.datatype = "port"
add_xray_depends(o, { xray_protocol = "vmess" })
add_xray_depends(o, { xray_protocol = "vless" })
add_xray_depends(o, { xray_protocol = "http" })
add_xray_depends(o, { xray_protocol = "socks" })
add_xray_depends(o, { xray_protocol = "shadowsocks" })
add_xray_depends(o, { xray_protocol = "trojan" })
add_xray_depends(o, { xray_protocol = "wireguard" })
add_v2ray_depends(o, { xray_protocol = "vmess" })
add_v2ray_depends(o, { xray_protocol = "vless" })
add_v2ray_depends(o, { xray_protocol = "http" })
add_v2ray_depends(o, { xray_protocol = "socks" })
add_v2ray_depends(o, { xray_protocol = "shadowsocks" })
add_v2ray_depends(o, { xray_protocol = "trojan" })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(Value, "xray_username", translate("Username"))
add_xray_depends(o, { xray_protocol = "http" })
add_xray_depends(o, { xray_protocol = "socks" })
add_v2ray_depends(o, { xray_protocol = "http" })
add_v2ray_depends(o, { xray_protocol = "socks" })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(Value, "xray_password", translate("Password"))
o.password = true
add_xray_depends(o, { xray_protocol = "http" })
add_xray_depends(o, { xray_protocol = "socks" })
add_xray_depends(o, { xray_protocol = "shadowsocks" })
add_xray_depends(o, { xray_protocol = "trojan" })
add_v2ray_depends(o, { xray_protocol = "http" })
add_v2ray_depends(o, { xray_protocol = "socks" })
add_v2ray_depends(o, { xray_protocol = "shadowsocks" })
add_v2ray_depends(o, { xray_protocol = "trojan" })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(ListValue, "security", translate("Encrypt Method"))
for a, t in ipairs(security_list) do o:value(t) end
add_xray_depends(o, { xray_protocol = "vmess" })
add_v2ray_depends(o, { xray_protocol = "vmess" })

o = s:option(Value, "encryption", translate("Encrypt Method"))
o.default = "none"
o:value("none")
add_xray_depends(o, { xray_protocol = "vless" })
add_v2ray_depends(o, { xray_protocol = "vless" })

o = s:option(ListValue, "v_ss_encrypt_method", translate("Encrypt Method"))
for a, t in ipairs(v_ss_encrypt_method_list) do o:value(t) end
add_v2ray_depends(o, { xray_protocol = "shadowsocks" })
function o.cfgvalue(self, section)
	return m:get(section, "method")
end
function o.write(self, section, value)
	m:set(section, "method", value)
end

o = s:option(ListValue, "x_ss_encrypt_method", translate("Encrypt Method"))
for a, t in ipairs(x_ss_encrypt_method_list) do o:value(t) end
add_xray_depends(o, { xray_protocol = "shadowsocks" })
function o.cfgvalue(self, section)
	return m:get(section, "method")
end
function o.write(self, section, value)
	m:set(section, "method", value)
end

o = s:option(Flag, "iv_check", translate("IV Check"))
add_v2ray_depends(o, { xray_protocol = "shadowsocks" })
add_xray_depends(o, { xray_protocol = "shadowsocks", x_ss_encrypt_method = "aes-128-gcm" })
add_xray_depends(o, { xray_protocol = "shadowsocks", x_ss_encrypt_method = "aes-256-gcm" })
add_xray_depends(o, { xray_protocol = "shadowsocks", x_ss_encrypt_method = "chacha20-poly1305" })
add_xray_depends(o, { xray_protocol = "shadowsocks", x_ss_encrypt_method = "xchacha20-poly1305" })

o = s:option(Flag, "uot", translate("UDP over TCP"), translate("Need Xray-core or sing-box as server side."))
add_xray_depends(o, { xray_protocol = "shadowsocks", x_ss_encrypt_method = "2022-blake3-aes-128-gcm" })
add_xray_depends(o, { xray_protocol = "shadowsocks", x_ss_encrypt_method = "2022-blake3-aes-256-gcm" })
add_xray_depends(o, { xray_protocol = "shadowsocks", x_ss_encrypt_method = "2022-blake3-chacha20-poly1305" })

o = s:option(Value, "xray_uuid", translate("ID"))
o.password = true
add_xray_depends(o, { xray_protocol = "vmess" })
add_xray_depends(o, { xray_protocol = "vless" })
add_v2ray_depends(o, { xray_protocol = "vmess" })
add_v2ray_depends(o, { xray_protocol = "vless" })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(Flag, "xray_tls", translate("TLS"))
o.default = 0
add_xray_depends(o, { xray_protocol = "vmess" })
add_xray_depends(o, { xray_protocol = "vless" })
add_xray_depends(o, { xray_protocol = "socks" })
add_xray_depends(o, { xray_protocol = "trojan" })
add_xray_depends(o, { xray_protocol = "shadowsocks" })
add_v2ray_depends(o, { xray_protocol = "vmess" })
add_v2ray_depends(o, { xray_protocol = "vless" })
add_v2ray_depends(o, { xray_protocol = "socks" })
add_v2ray_depends(o, { xray_protocol = "trojan" })
add_v2ray_depends(o, { xray_protocol = "shadowsocks" })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(Value, "xray_tlsflow", translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:value("xtls-rprx-vision-udp443")
add_xray_depends(o, { xray_protocol = "vless", xray_tls = true, transport = "tcp" })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(Flag, "reality", translate("REALITY"), translate("Only recommend to use with VLESS-TCP-XTLS-Vision."))
o.default = 0
add_xray_depends(o, { xray_tls = true, transport = "tcp" })
add_xray_depends(o, { xray_tls = true, transport = "h2" })
add_xray_depends(o, { xray_tls = true, transport = "grpc" })

o = s:option(ListValue, "alpn", translate("alpn"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h2,http/1.1")
o:value("h2")
o:value("http/1.1")
add_xray_depends(o, { xray_tls = true, reality = false })
add_v2ray_depends(o, { xray_tls = true })

-- o = s:option(Value, "minversion", translate("minversion"))
-- o.default = "1.3"
-- o:value("1.3")
-- add_xray_depends(o, { xray_tls = true })
-- add_v2ray_depends(o, { xray_tls = true })

o = s:option(Value, "xray_tls_serverName", translate("Domain"))
add_xray_depends(o, { xray_tls = true })
add_v2ray_depends(o, { xray_tls = true })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(Flag, "xray_tls_allowInsecure", translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"
add_xray_depends(o, { xray_tls = true, reality = false })
add_v2ray_depends(o, { xray_tls = true })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(Value, "xray_fingerprint", translate("Finger Print"), translate("Avoid using randomized, unless you have to."))
o:value("", translate("Disable"))
o:value("chrome")
o:value("firefox")
o:value("safari")
o:value("ios")
-- o:value("android")
o:value("edge")
-- o:value("360")
o:value("qq")
o:value("random")
o:value("randomized")
o.default = ""
add_xray_depends(o, { xray_tls = true, reality = false })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write
o.remove = rm_prefix_remove

-- [[ REALITY部分 ]] --
o = s:option(Value, "reality_publicKey", translate("Public Key"))
add_xray_depends(o, { xray_tls = true, reality = true })

o = s:option(Value, "reality_shortId", translate("Short Id"))
add_xray_depends(o, { xray_tls = true, reality = true })

o = s:option(Value, "reality_spiderX", translate("Spider X"))
o.placeholder = "/"
add_xray_depends(o, { xray_tls = true, reality = true })

o = s:option(Value, "reality_fingerprint", translate("Finger Print"), translate("Avoid using randomized, unless you have to."))
o:value("chrome")
o:value("firefox")
o:value("safari")
o:value("ios")
-- o:value("android")
o:value("edge")
-- o:value("360")
o:value("qq")
o:value("random")
o:value("randomized")
o.default = "chrome"
add_xray_depends(o, { xray_tls = true, reality = true })
function o.cfgvalue(self, section)
	return m:get(section, "fingerprint")
end
function o.write(self, section, value)
	m:set(section, "fingerprint", value)
end

o = s:option(ListValue, "transport", translate("Transport"))
o:value("tcp", "TCP")
o:value("mkcp", "mKCP")
o:value("ws", "WebSocket")
o:value("h2", "HTTP/2")
o:value("ds", "DomainSocket")
o:value("quic", "QUIC")
o:value("grpc", "gRPC")
add_xray_depends(o, { xray_protocol = "vmess" })
add_xray_depends(o, { xray_protocol = "vless" })
add_xray_depends(o, { xray_protocol = "socks" })
add_xray_depends(o, { xray_protocol = "shadowsocks" })
add_xray_depends(o, { xray_protocol = "trojan" })
add_v2ray_depends(o, { xray_protocol = "vmess" })
add_v2ray_depends(o, { xray_protocol = "vless" })
add_v2ray_depends(o, { xray_protocol = "socks" })
add_v2ray_depends(o, { xray_protocol = "shadowsocks" })
add_v2ray_depends(o, { xray_protocol = "trojan" })

--[[
o = s:option(ListValue, "ss_transport", translate("Transport"))
o:value("ws", "WebSocket")
o:value("h2", "HTTP/2")
o:value("h2+ws", "HTTP/2 & WebSocket")
add_xray_depends(o, { xray_protocol = "shadowsocks" })
add_v2ray_depends(o, { xray_protocol = "shadowsocks" })
]]--

o = s:option(Value, "wireguard_public_key", translate("Public Key"))
add_xray_depends(o, { xray_protocol = "wireguard" })

o = s:option(Value, "wireguard_secret_key", translate("Private Key"))
add_xray_depends(o, { xray_protocol = "wireguard" })

o = s:option(Value, "wireguard_preSharedKey", translate("Pre shared key"))
add_xray_depends(o, { xray_protocol = "wireguard" })

o = s:option(DynamicList, "wireguard_local_address", translate("Local Address"))
add_xray_depends(o, { xray_protocol = "wireguard" })

o = s:option(Value, "wireguard_mtu", translate("MTU"))
o.default = "1420"
add_xray_depends(o, { xray_protocol = "wireguard" })

if api.compare_versions(api.get_app_version("xray"), ">=", "1.8.0") then
	o = s:option(Value, "wireguard_reserved", translate("Reserved"), translate("Decimal numbers separated by \",\" or Base64-encoded strings."))
	add_xray_depends(o, { xray_protocol = "wireguard" })
end

o = s:option(Value, "wireguard_keepAlive", translate("Keep Alive"))
o.default = "0"
add_xray_depends(o, { xray_protocol = "wireguard" })

-- [[ TCP部分 ]]--

-- TCP伪装
o = s:option(ListValue, "tcp_guise", translate("Camouflage Type"))
o:value("none", "none")
o:value("http", "http")
add_xray_depends(o, { transport = "tcp" })
add_v2ray_depends(o, { transport = "tcp" })

-- HTTP域名
o = s:option(DynamicList, "tcp_guise_http_host", translate("HTTP Host"))
add_xray_depends(o, { tcp_guise = "http" })
add_v2ray_depends(o, { tcp_guise = "http" })

-- HTTP路径
o = s:option(DynamicList, "tcp_guise_http_path", translate("HTTP Path"))
o.placeholder = "/"
add_xray_depends(o, { tcp_guise = "http" })
add_v2ray_depends(o, { tcp_guise = "http" })

-- [[ mKCP部分 ]]--

o = s:option(ListValue, "mkcp_guise", translate("Camouflage Type"), translate('<br />none: default, no masquerade, data sent is packets with no characteristics.<br />srtp: disguised as an SRTP packet, it will be recognized as video call data (such as FaceTime).<br />utp: packets disguised as uTP will be recognized as bittorrent downloaded data.<br />wechat-video: packets disguised as WeChat video calls.<br />dtls: disguised as DTLS 1.2 packet.<br />wireguard: disguised as a WireGuard packet. (not really WireGuard protocol)'))
for a, t in ipairs(header_type_list) do o:value(t) end
add_xray_depends(o, { transport = "mkcp" })
add_v2ray_depends(o, { transport = "mkcp" })

o = s:option(Value, "mkcp_mtu", translate("KCP MTU"))
o.default = "1350"
add_xray_depends(o, { transport = "mkcp" })
add_v2ray_depends(o, { transport = "mkcp" })

o = s:option(Value, "mkcp_tti", translate("KCP TTI"))
o.default = "20"
add_xray_depends(o, { transport = "mkcp" })
add_v2ray_depends(o, { transport = "mkcp" })

o = s:option(Value, "mkcp_uplinkCapacity", translate("KCP uplinkCapacity"))
o.default = "5"
add_xray_depends(o, { transport = "mkcp" })
add_v2ray_depends(o, { transport = "mkcp" })

o = s:option(Value, "mkcp_downlinkCapacity", translate("KCP downlinkCapacity"))
o.default = "20"
add_xray_depends(o, { transport = "mkcp" })
add_v2ray_depends(o, { transport = "mkcp" })

o = s:option(Flag, "mkcp_congestion", translate("KCP Congestion"))
add_xray_depends(o, { transport = "mkcp" })
add_v2ray_depends(o, { transport = "mkcp" })

o = s:option(Value, "mkcp_readBufferSize", translate("KCP readBufferSize"))
o.default = "1"
add_xray_depends(o, { transport = "mkcp" })
add_v2ray_depends(o, { transport = "mkcp" })

o = s:option(Value, "mkcp_writeBufferSize", translate("KCP writeBufferSize"))
o.default = "1"
add_xray_depends(o, { transport = "mkcp" })
add_v2ray_depends(o, { transport = "mkcp" })

o = s:option(Value, "mkcp_seed", translate("KCP Seed"))
add_xray_depends(o, { transport = "mkcp" })
add_v2ray_depends(o, { transport = "mkcp" })

-- [[ WebSocket部分 ]]--
o = s:option(Value, "xray_ws_host", translate("WebSocket Host"))
add_xray_depends(o, { transport = "ws" })
add_xray_depends(o, { ss_transport = "ws" })
add_v2ray_depends(o, { transport = "ws" })
add_v2ray_depends(o, { ss_transport = "ws" })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(Value, "xray_ws_path", translate("WebSocket Path"))
o.placeholder = "/"
add_xray_depends(o, { transport = "ws" })
add_xray_depends(o, { ss_transport = "ws" })
add_v2ray_depends(o, { transport = "ws" })
add_v2ray_depends(o, { ss_transport = "ws" })
o.cfgvalue = rm_prefix_cfgvalue
o.write = rm_prefix_write

o = s:option(Flag, "ws_enableEarlyData", translate("Enable early data"))
add_v2ray_depends(o, { transport = "ws" })

o = s:option(Value, "ws_maxEarlyData", translate("Early data length"))
o.default = "1024"
add_v2ray_depends(o, { ws_enableEarlyData = true })

o = s:option(Value, "ws_earlyDataHeaderName", translate("Early data header name"), translate("Recommended value: Sec-WebSocket-Protocol"))
add_v2ray_depends(o, { ws_enableEarlyData = true })

-- [[ HTTP/2部分 ]]--
o = s:option(Value, "xray_h2_host", translate("HTTP/2 Host"))
add_xray_depends(o, { transport = "h2" })
add_xray_depends(o, { ss_transport = "h2" })
add_v2ray_depends(o, { transport = "h2" })
add_v2ray_depends(o, { ss_transport = "h2" })

o = s:option(Value, "xray_h2_path", translate("HTTP/2 Path"))
o.placeholder = "/"
add_xray_depends(o, { transport = "h2" })
add_xray_depends(o, { ss_transport = "h2" })
add_v2ray_depends(o, { transport = "h2" })
add_v2ray_depends(o, { ss_transport = "h2" })

o = s:option(Flag, "h2_health_check", translate("Health check"))
add_xray_depends(o, { transport = "h2" })

o = s:option(Value, "h2_read_idle_timeout", translate("Idle timeout"))
o.default = "10"
add_xray_depends(o, { h2_health_check = true })

o = s:option(Value, "h2_health_check_timeout", translate("Health check timeout"))
o.default = "15"
add_xray_depends(o, { h2_health_check = true })

-- [[ DomainSocket部分 ]]--
o = s:option(Value, "ds_path", "Path", translate("A legal file path. This file must not exist before running."))
add_xray_depends(o, { transport = "ds" })
add_v2ray_depends(o, { transport = "ds" })

-- [[ QUIC部分 ]]--
o = s:option(ListValue, "quic_security", translate("Encrypt Method"))
o:value("none")
o:value("aes-128-gcm")
o:value("chacha20-poly1305")
add_xray_depends(o, { transport = "quic" })
add_v2ray_depends(o, { transport = "quic" })

o = s:option(Value, "quic_key", translate("Encrypt Method") .. translate("Key"))
add_xray_depends(o, { transport = "quic" })
add_v2ray_depends(o, { transport = "quic" })

o = s:option(ListValue, "quic_guise", translate("Camouflage Type"))
for a, t in ipairs(header_type_list) do o:value(t) end
add_xray_depends(o, { transport = "quic" })
add_v2ray_depends(o, { transport = "quic" })

-- [[ gRPC部分 ]]--
o = s:option(Value, "grpc_serviceName", "ServiceName")
add_xray_depends(o, { transport = "grpc" })
add_v2ray_depends(o, { transport = "grpc" })

o = s:option(ListValue, "grpc_mode", "gRPC " .. translate("Transfer mode"))
o:value("gun")
o:value("multi")
add_xray_depends(o, { transport = "grpc" })

o = s:option(Flag, "grpc_health_check", translate("Health check"))
add_xray_depends(o, { transport = "grpc" })

o = s:option(Value, "grpc_idle_timeout", translate("Idle timeout"))
o.default = "10"
add_xray_depends(o, { grpc_health_check = true })

o = s:option(Value, "grpc_health_check_timeout", translate("Health check timeout"))
o.default = "20"
add_xray_depends(o, { grpc_health_check = true })

o = s:option(Flag, "grpc_permit_without_stream", translate("Permit without stream"))
o.default = "0"
add_xray_depends(o, { grpc_health_check = true })

o = s:option(Value, "grpc_initial_windows_size", translate("Initial Windows Size"))
o.default = "0"
add_xray_depends(o, { transport = "grpc" })

-- [[ Mux ]]--
o = s:option(Flag, "mux", translate("Mux"))
add_v2ray_depends(o, { xray_protocol = "vmess" })
add_v2ray_depends(o, { xray_protocol = "vless" })
add_v2ray_depends(o, { xray_protocol = "http" })
add_v2ray_depends(o, { xray_protocol = "socks" })
add_v2ray_depends(o, { xray_protocol = "shadowsocks" })
add_v2ray_depends(o, { xray_protocol = "trojan" })
add_xray_depends(o, { xray_protocol = "vmess" })
add_xray_depends(o, { xray_protocol = "vless", xray_tlsflow = "" })
add_xray_depends(o, { xray_protocol = "http" })
add_xray_depends(o, { xray_protocol = "socks" })
add_xray_depends(o, { xray_protocol = "shadowsocks" })
add_xray_depends(o, { xray_protocol = "trojan" })

o = s:option(Value, "mux_concurrency", translate("Mux concurrency"))
o.default = 8
add_xray_depends(o, { mux = true })
add_v2ray_depends(o, { mux = true })

-- [[ XUDP Mux ]]--
o = s:option(Flag, "xmux", translate("xMux"))
o.default = 1
add_xray_depends(o, { xray_protocol = "vless", xray_tlsflow = "xtls-rprx-vision" })
add_xray_depends(o, { xray_protocol = "vless", xray_tlsflow = "xtls-rprx-vision-udp443" })

o = s:option(Value, "xudp_concurrency", translate("XUDP Mux concurrency"))
o.default = 8
add_xray_depends(o, { xmux = true })

s.fields["xray_protocol"].validate = function(self, value)
	if value == "_shunt" or value == "_balancing" then
		s.fields["xray_address"].rmempty = true
		s.fields["xray_port"].rmempty = true
	end
	return value
end
