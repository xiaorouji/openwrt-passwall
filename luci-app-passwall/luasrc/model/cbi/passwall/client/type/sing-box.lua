local m, s = ...

local api = require "luci.passwall.api"

local singbox_bin = api.finded_com("singbox")

if not singbox_bin then
	return
end

local singbox_tags = luci.sys.exec(singbox_bin .. " version  | grep 'Tags:' | awk '{print $2}'")

local appname = "passwall"

local type_name = "sing-box"

local option_prefix = "singbox_"

local function _n(name)
	return option_prefix .. name
end

local ss_method_new_list = {
	"none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

local ss_method_old_list = {
	"aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20",
}

local security_list = { "none", "auto", "aes-128-gcm", "chacha20-poly1305", "zero" }

-- [[ sing-box ]]

s.fields["type"]:value(type_name, "Sing-Box")

o = s:option(ListValue, _n("protocol"), translate("Protocol"))
o:value("socks", "Socks")
o:value("http", "HTTP")
o:value("shadowsocks", "Shadowsocks")
if singbox_tags:find("with_shadowsocksr") then
	o:value("shadowsocksr", "ShadowsocksR")
end
o:value("vmess", "Vmess")
o:value("trojan", "Trojan")
if singbox_tags:find("with_wireguard") then
	o:value("wireguard", "WireGuard")
end
if singbox_tags:find("with_quic") then
	o:value("hysteria", "Hysteria")
end
o:value("vless", "VLESS")
if singbox_tags:find("with_quic") then
	o:value("tuic", "TUIC")
end
if singbox_tags:find("with_quic") then
	o:value("hysteria2", "Hysteria2")
end
o:value("_urltest", translate("URLTest"))
o:value("_shunt", translate("Shunt"))
o:value("_iface", translate("Custom Interface"))

o = s:option(Value, _n("iface"), translate("Interface"))
o.default = "eth1"
o:depends({ [_n("protocol")] = "_iface" })

local nodes_table = {}
local iface_table = {}
local urltest_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = {
			id = e[".name"],
			remark = e["remark"],
			type = e["type"]
		}
	end
	if e.protocol == "_iface" then
		iface_table[#iface_table + 1] = {
			id = e[".name"],
			remark = e["remark"]
		}
	end
	if e.protocol == "_urltest" then
		urltest_table[#urltest_table + 1] = {
			id = e[".name"],
			remark = e["remark"]
		}
	end
end

local socks_list = {}
m.uci:foreach(appname, "socks", function(s)
	if s.enabled == "1" and s.node then
		socks_list[#socks_list + 1] = {
			id = "Socks_" .. s[".name"],
			remark = translate("Socks Config") .. " " .. string.format("[%s %s]", s.port, translate("Port"))
		}
	end
end)

--[[ URLTest ]]
o = s:option(DynamicList, _n("urltest_node"), translate("URLTest node list"), translate("List of nodes to test, <a target='_blank' href='https://sing-box.sagernet.org/configuration/outbound/urltest'>document</a>"))
o:depends({ [_n("protocol")] = "_urltest" })
for k, v in pairs(nodes_table) do o:value(v.id, v.remark) end

o = s:option(Value, _n("urltest_url"), translate("Probe URL"))
o:depends({ [_n("protocol")] = "_urltest" })
o:value("https://cp.cloudflare.com/", "Cloudflare")
o:value("https://www.gstatic.com/generate_204", "Gstatic")
o:value("https://www.google.com/generate_204", "Google")
o:value("https://www.youtube.com/generate_204", "YouTube")
o:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
o:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
o.default = "https://www.gstatic.com/generate_204"
o.description = translate("The URL used to detect the connection status.")

o = s:option(Value, _n("urltest_interval"), translate("Test interval"))
o:depends({ [_n("protocol")] = "_urltest" })
o.datatype = "uinteger"
o.default = "180"
o.description = translate("The test interval in seconds.") .. "<br />" ..
		translate("Test interval must be less or equal than idle timeout.")

o = s:option(Value, _n("urltest_tolerance"), translate("Test tolerance"), translate("The test tolerance in milliseconds."))
o:depends({ [_n("protocol")] = "_urltest" })
o.datatype = "uinteger"
o.default = "50"

o = s:option(Value, _n("urltest_idle_timeout"), translate("Idle timeout"), translate("The idle timeout in seconds."))
o:depends({ [_n("protocol")] = "_urltest" })
o.datatype = "uinteger"
o.default = "1800"

o = s:option(Flag, _n("urltest_interrupt_exist_connections"), translate("Interrupt existing connections"))
o:depends({ [_n("protocol")] = "_urltest" })
o.default = "0"
o.description = translate("Interrupt existing connections when the selected outbound has changed.") 

-- [[ 分流模块 ]]
if #nodes_table > 0 then
	o = s:option(Flag, _n("preproxy_enabled"), translate("Preproxy"))
	o:depends({ [_n("protocol")] = "_shunt" })

	o = s:option(ListValue, _n("main_node"), string.format('<a style="color:red">%s</a>', translate("Preproxy Node")), translate("Set the node to be used as a pre-proxy. Each rule (including <code>Default</code>) has a separate switch that controls whether this rule uses the pre-proxy or not."))
	o:depends({ [_n("protocol")] = "_shunt", [_n("preproxy_enabled")] = true })
	for k, v in pairs(socks_list) do
		o:value(v.id, v.remark)
	end
	for k, v in pairs(urltest_table) do
		o:value(v.id, v.remark)
	end
	for k, v in pairs(iface_table) do
		o:value(v.id, v.remark)
	end
	for k, v in pairs(nodes_table) do
		o:value(v.id, v.remark)
	end
end
m.uci:foreach(appname, "shunt_rules", function(e)
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
			for k, v in pairs(urltest_table) do
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
	for k, v in pairs(urltest_table) do
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
o:depends({ [_n("protocol")] = "shadowsocksr" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "tuic" })

o = s:option(ListValue, _n("security"), translate("Encrypt Method"))
for a, t in ipairs(security_list) do o:value(t) end
o:depends({ [_n("protocol")] = "vmess" })

o = s:option(ListValue, _n("ss_method"), translate("Encrypt Method"))
o.rewrite_option = "method"
for a, t in ipairs(ss_method_new_list) do o:value(t) end
for a, t in ipairs(ss_method_old_list) do o:value(t) end
o:depends({ [_n("protocol")] = "shadowsocks" })

if singbox_tags:find("with_shadowsocksr") then
	o = s:option(ListValue, _n("ssr_method"), translate("Encrypt Method"))
	o.rewrite_option = "method"
	for a, t in ipairs(ss_method_old_list) do o:value(t) end
	o:depends({ [_n("protocol")] = "shadowsocksr" })

	local ssr_protocol_list = {
		"origin", "verify_simple", "verify_deflate", "verify_sha1", "auth_simple",
		"auth_sha1", "auth_sha1_v2", "auth_sha1_v4", "auth_aes128_md5",
		"auth_aes128_sha1", "auth_chain_a", "auth_chain_b", "auth_chain_c",
		"auth_chain_d", "auth_chain_e", "auth_chain_f"
	}

	o = s:option(ListValue, _n("ssr_protocol"), translate("Protocol"))
	for a, t in ipairs(ssr_protocol_list) do o:value(t) end
	o:depends({ [_n("protocol")] = "shadowsocksr" })

	o = s:option(Value, _n("ssr_protocol_param"), translate("Protocol_param"))
	o:depends({ [_n("protocol")] = "shadowsocksr" })

	local ssr_obfs_list = {
		"plain", "http_simple", "http_post", "random_head", "tls_simple",
		"tls1.0_session_auth", "tls1.2_ticket_auth"
	}

	o = s:option(ListValue, _n("ssr_obfs"), translate("Obfs"))
	for a, t in ipairs(ssr_obfs_list) do o:value(t) end
	o:depends({ [_n("protocol")] = "shadowsocksr" })

	o = s:option(Value, _n("ssr_obfs_param"), translate("Obfs_param"))
	o:depends({ [_n("protocol")] = "shadowsocksr" })
end

o = s:option(Flag, _n("uot"), translate("UDP over TCP"))
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Value, _n("uuid"), translate("ID"))
o.password = true
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "tuic" })

o = s:option(Value, _n("alter_id"), "Alter ID")
o.datatype = "uinteger"
o.default = "0"
o:depends({ [_n("protocol")] = "vmess" })

o = s:option(Flag, _n("global_padding"), "global_padding", translate("Protocol parameter. Will waste traffic randomly if enabled."))
o.default = "0"
o:depends({ [_n("protocol")] = "vmess" })

o = s:option(Flag, _n("authenticated_length"), "authenticated_length", translate("Protocol parameter. Enable length block encryption."))
o.default = "0"
o:depends({ [_n("protocol")] = "vmess" })

o = s:option(ListValue, _n("flow"), translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:depends({ [_n("protocol")] = "vless", [_n("tls")] = true })

if singbox_tags:find("with_quic") then
	o = s:option(Value, _n("hysteria_obfs"), translate("Obfs Password"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(ListValue, _n("hysteria_auth_type"), translate("Auth Type"))
	o:value("disable", translate("Disable"))
	o:value("string", translate("STRING"))
	o:value("base64", translate("BASE64"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_auth_password"), translate("Auth Password"))
	o.password = true
	o:depends({ [_n("protocol")] = "hysteria", [_n("hysteria_auth_type")] = "string"})
	o:depends({ [_n("protocol")] = "hysteria", [_n("hysteria_auth_type")] = "base64"})

	o = s:option(Value, _n("hysteria_up_mbps"), translate("Max upload Mbps"))
	o.default = "10"
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_down_mbps"), translate("Max download Mbps"))
	o.default = "50"
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_recv_window_conn"), translate("QUIC stream receive window"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_recv_window"), translate("QUIC connection receive window"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Flag, _n("hysteria_disable_mtu_discovery"), translate("Disable MTU detection"))
	o:depends({ [_n("protocol")] = "hysteria" })

	o = s:option(Value, _n("hysteria_alpn"), translate("QUIC TLS ALPN"))
	o:depends({ [_n("protocol")] = "hysteria" })
end

if singbox_tags:find("with_quic") then
	o = s:option(ListValue, _n("tuic_congestion_control"), translate("Congestion control algorithm"))
	o.default = "cubic"
	o:value("bbr", translate("BBR"))
	o:value("cubic", translate("CUBIC"))
	o:value("new_reno", translate("New Reno"))
	o:depends({ [_n("protocol")] = "tuic" })

	o = s:option(ListValue, _n("tuic_udp_relay_mode"), translate("UDP relay mode"))
	o.default = "native"
	o:value("native", translate("native"))
	o:value("quic", translate("QUIC"))
	o:depends({ [_n("protocol")] = "tuic" })

	--[[
	o = s:option(Flag, _n("tuic_udp_over_stream"), translate("UDP over stream"))
	o:depends({ [_n("protocol")] = "tuic" })
	]]--

	o = s:option(Flag, _n("tuic_zero_rtt_handshake"), translate("Enable 0-RTT QUIC handshake"))
	o.default = 0
	o:depends({ [_n("protocol")] = "tuic" })

	o = s:option(Value, _n("tuic_heartbeat"), translate("Heartbeat interval(second)"))
	o.datatype = "uinteger"
	o.default = "3"
	o:depends({ [_n("protocol")] = "tuic" })

	o = s:option(ListValue, _n("tuic_alpn"), translate("QUIC TLS ALPN"))
	o.default = "default"
	o:value("default", translate("Default"))
	o:value("h3")
	o:value("h2")
	o:value("h3,h2")
	o:value("http/1.1")
	o:value("h2,http/1.1")
	o:value("h3,h2,http/1.1")
	o:depends({ [_n("protocol")] = "tuic" })
end

if singbox_tags:find("with_quic") then
	o = s:option(Value, _n("hysteria2_up_mbps"), translate("Max upload Mbps"))
	o:depends({ [_n("protocol")] = "hysteria2" })

	o = s:option(Value, _n("hysteria2_down_mbps"), translate("Max download Mbps"))
	o:depends({ [_n("protocol")] = "hysteria2" })

	o = s:option(ListValue, _n("hysteria2_obfs_type"), translate("Obfs Type"))
	o:value("", translate("Disable"))
	o:value("salamander")
	o:depends({ [_n("protocol")] = "hysteria2" })

	o = s:option(Value, _n("hysteria2_obfs_password"), translate("Obfs Password"))
	o:depends({ [_n("protocol")] = "hysteria2" })

	o = s:option(Value, _n("hysteria2_auth_password"), translate("Auth Password"))
	o.password = true
	o:depends({ [_n("protocol")] = "hysteria2"})
end

o = s:option(Flag, _n("tls"), translate("TLS"))
o.default = 0
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(ListValue, _n("alpn"), translate("alpn"))
o.default = "default"
o:value("default", translate("Default"))
o:value("h3")
o:value("h2")
o:value("h3,h2")
o:value("http/1.1")
o:value("h2,http/1.1")
o:value("h3,h2,http/1.1")
o:depends({ [_n("tls")] = true })

o = s:option(Value, _n("tls_serverName"), translate("Domain"))
o:depends({ [_n("tls")] = true })
o:depends({ [_n("protocol")] = "hysteria"})
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria2" })
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(Flag, _n("tls_allowInsecure"), translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"
o:depends({ [_n("tls")] = true })
o:depends({ [_n("protocol")] = "hysteria"})
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria2" })
o:depends({ [_n("protocol")] = "shadowsocks" })

if singbox_tags:find("with_ech") then
	o = s:option(Flag, _n("ech"), translate("ECH"))
	o.default = "0"
	o:depends({ [_n("tls")] = true, [_n("flow")] = "", [_n("reality")] = false })
	o:depends({ [_n("protocol")] = "tuic" })
	o:depends({ [_n("protocol")] = "hysteria" })
	o:depends({ [_n("protocol")] = "hysteria2" })

	o = s:option(TextValue, _n("ech_config"), translate("ECH Config"))
	o.default = ""
	o.rows = 5
	o.wrap = "off"
	o:depends({ [_n("ech")] = true })
	o.validate = function(self, value)
		value = value:gsub("^%s+", ""):gsub("%s+$","\n"):gsub("\r\n","\n"):gsub("[ \t]*\n[ \t]*", "\n")
		value = value:gsub("^%s*\n", "")
		if value:sub(-1) == "\n" then  
			value = value:sub(1, -2)  
		end
		return value
	end

	o = s:option(Flag, _n("pq_signature_schemes_enabled"), translate("PQ signature schemes"))
	o.default = "0"
	o:depends({ [_n("ech")] = true })

	o = s:option(Flag, _n("dynamic_record_sizing_disabled"), translate("Disable adaptive sizing of TLS records"))
	o.default = "0"
	o:depends({ [_n("ech")] = true })
end

if singbox_tags:find("with_utls") then
	o = s:option(Flag, _n("utls"), translate("uTLS"))
	o.default = "0"
	o:depends({ [_n("tls")] = true })

	o = s:option(ListValue, _n("fingerprint"), translate("Finger Print"))
	o:value("chrome")
	o:value("firefox")
	o:value("edge")
	o:value("safari")
	-- o:value("360")
	o:value("qq")
	o:value("ios")
	-- o:value("android")
	o:value("random")
	-- o:value("randomized")
	o.default = "chrome"
	o:depends({ [_n("tls")] = true, [_n("utls")] = true })

	-- [[ REALITY部分 ]] --
	o = s:option(Flag, _n("reality"), translate("REALITY"))
	o.default = 0
	o:depends({ [_n("protocol")] = "vless", [_n("utls")] = true })
	o:depends({ [_n("protocol")] = "vmess", [_n("utls")] = true })
	o:depends({ [_n("protocol")] = "shadowsocks", [_n("utls")] = true })
	o:depends({ [_n("protocol")] = "socks", [_n("utls")] = true })
	o:depends({ [_n("protocol")] = "trojan", [_n("utls")] = true })
	
	o = s:option(Value, _n("reality_publicKey"), translate("Public Key"))
	o:depends({ [_n("utls")] = true, [_n("reality")] = true })
	
	o = s:option(Value, _n("reality_shortId"), translate("Short Id"))
	o:depends({ [_n("utls")] = true, [_n("reality")] = true })
end

o = s:option(ListValue, _n("transport"), translate("Transport"))
o:value("tcp", "TCP")
o:value("http", "HTTP")
o:value("ws", "WebSocket")
o:value("httpupgrade", "HTTPUpgrade")
if singbox_tags:find("with_quic") then
	o:value("quic", "QUIC")
end
if singbox_tags:find("with_grpc") then
	o:value("grpc", "gRPC")
else o:value("grpc", "gRPC-lite")
end
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "trojan" })

if singbox_tags:find("with_wireguard") then
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

	o = s:option(Value, _n("wireguard_reserved"), translate("Reserved"), translate("Decimal numbers separated by \",\" or Base64-encoded strings."))
	o:depends({ [_n("protocol")] = "wireguard" })
end

-- [[ HTTP部分 ]]--
o = s:option(Value, _n("http_host"), translate("HTTP Host"))
o:depends({ [_n("transport")] = "http" })

o = s:option(Value, _n("http_path"), translate("HTTP Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "http" })

o = s:option(Flag, _n("http_h2_health_check"), translate("Health check"))
o:depends({ [_n("tls")] = true, [_n("transport")] = "http" })

o = s:option(Value, _n("http_h2_read_idle_timeout"), translate("Idle timeout"))
o.default = "10"
o:depends({ [_n("tls")] = true, [_n("transport")] = "http", [_n("http_h2_health_check")] = true })

o = s:option(Value, _n("http_h2_health_check_timeout"), translate("Health check timeout"))
o.default = "15"
o:depends({ [_n("tls")] = true, [_n("transport")] = "http", [_n("http_h2_health_check")] = true })

-- [[ WebSocket部分 ]]--
o = s:option(Value, _n("ws_host"), translate("WebSocket Host"))
o:depends({ [_n("transport")] = "ws" })

o = s:option(Value, _n("ws_path"), translate("WebSocket Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "ws" })

o = s:option(Flag, _n("ws_enableEarlyData"), translate("Enable early data"))
o:depends({ [_n("transport")] = "ws" })

o = s:option(Value, _n("ws_maxEarlyData"), translate("Early data length"))
o.default = "1024"
o:depends({ [_n("ws_enableEarlyData")] = true })

o = s:option(Value, _n("ws_earlyDataHeaderName"), translate("Early data header name"), translate("Recommended value: Sec-WebSocket-Protocol"))
o:depends({ [_n("ws_enableEarlyData")] = true })

-- [[ HTTPUpgrade部分 ]]--
o = s:option(Value, _n("httpupgrade_host"), translate("HTTPUpgrade Host"))
o:depends({ [_n("transport")] = "httpupgrade" })

o = s:option(Value, _n("httpupgrade_path"), translate("HTTPUpgrade Path"))
o.placeholder = "/"
o:depends({ [_n("transport")] = "httpupgrade" })

-- [[ gRPC部分 ]]--
o = s:option(Value, _n("grpc_serviceName"), "ServiceName")
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

-- [[ Mux ]]--
o = s:option(Flag, _n("mux"), translate("Mux"))
o.rmempty = false
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "vless", [_n("flow")] = "" })
o:depends({ [_n("protocol")] = "shadowsocks", [_n("uot")] = "" })
o:depends({ [_n("protocol")] = "trojan" })

o = s:option(ListValue, _n("mux_type"), translate("Mux"))
o:value("smux")
o:value("yamux")
o:value("h2mux")
o:depends({ [_n("mux")] = true })

o = s:option(Value, _n("mux_concurrency"), translate("Mux concurrency"))
o.default = 4
o:depends({ [_n("mux")] = true, [_n("tcpbrutal")] = false })

o = s:option(Flag, _n("mux_padding"), translate("Padding"))
o.default = 0
o:depends({ [_n("mux")] = true })

-- [[ TCP Brutal ]]--
o = s:option(Flag, _n("tcpbrutal"), translate("TCP Brutal"))
o.default = 0
o:depends({ [_n("mux")] = true })

o = s:option(Value, _n("tcpbrutal_up_mbps"), translate("Max upload Mbps"))
o.default = "10"
o:depends({ [_n("tcpbrutal")] = true })

o = s:option(Value, _n("tcpbrutal_down_mbps"), translate("Max download Mbps"))
o.default = "50"
o:depends({ [_n("tcpbrutal")] = true })

o = s:option(Flag, _n("shadowtls"), "ShadowTLS")
o.default = 0
o:depends({ [_n("protocol")] = "vmess", [_n("tls")] = false })
o:depends({ [_n("protocol")] = "shadowsocks", [_n("tls")] = false })

o = s:option(ListValue, _n("shadowtls_version"), "ShadowTLS " .. translate("Version"))
o.default = "1"
o:value("1", "ShadowTLS v1")
o:value("2", "ShadowTLS v2")
o:value("3", "ShadowTLS v3")
o:depends({ [_n("shadowtls")] = true })

o = s:option(Value, _n("shadowtls_password"), "ShadowTLS " .. translate("Password"))
o.password = true
o:depends({ [_n("shadowtls")] = true, [_n("shadowtls_version")] = "2" })
o:depends({ [_n("shadowtls")] = true, [_n("shadowtls_version")] = "3" })

o = s:option(Value, _n("shadowtls_serverName"), "ShadowTLS " .. translate("Domain"))
o:depends({ [_n("shadowtls")] = true })

if singbox_tags:find("with_utls") then
	o = s:option(Flag, _n("shadowtls_utls"), "ShadowTLS " .. translate("uTLS"))
	o.default = "0"
	o:depends({ [_n("shadowtls")] = true })

	o = s:option(ListValue, _n("shadowtls_fingerprint"), "ShadowTLS " .. translate("Finger Print"))
	o:value("chrome")
	o:value("firefox")
	o:value("edge")
	o:value("safari")
	-- o:value("360")
	o:value("qq")
	o:value("ios")
	-- o:value("android")
	o:value("random")
	-- o:value("randomized")
	o.default = "chrome"
	o:depends({ [_n("shadowtls")] = true, [_n("shadowtls_utls")] = true })
end

-- [[ SIP003 plugin ]]--
o = s:option(Flag, _n("plugin_enabled"), translate("plugin"))
o.default = 0
o:depends({ [_n("protocol")] = "shadowsocks" })

o = s:option(ListValue, _n("plugin"), "SIP003 " .. translate("plugin"))
o.default = "obfs-local"
o:depends({ [_n("plugin_enabled")] = true })
o:value("obfs-local")
o:value("v2ray-plugin")

o = s:option(Value, _n("plugin_opts"), translate("opts"))
o:depends({ [_n("plugin_enabled")] = true })

o = s:option(ListValue, _n("domain_strategy"), translate("Domain Strategy"), translate("If is domain name, The requested domain name will be resolved to IP before connect."))
o.default = ""
o:value("", translate("Auto"))
o:value("prefer_ipv4", translate("Prefer IPv4"))
o:value("prefer_ipv6", translate("Prefer IPv6"))
o:value("ipv4_only", translate("IPv4 Only"))
o:value("ipv6_only", translate("IPv6 Only"))
o:depends({ [_n("protocol")] = "socks" })
o:depends({ [_n("protocol")] = "http" })
o:depends({ [_n("protocol")] = "shadowsocks" })
o:depends({ [_n("protocol")] = "shadowsocksr" })
o:depends({ [_n("protocol")] = "vmess" })
o:depends({ [_n("protocol")] = "trojan" })
o:depends({ [_n("protocol")] = "wireguard" })
o:depends({ [_n("protocol")] = "hysteria" })
o:depends({ [_n("protocol")] = "vless" })
o:depends({ [_n("protocol")] = "tuic" })
o:depends({ [_n("protocol")] = "hysteria2" })

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
	if v.type == "sing-box" and v.id ~= arg[1] then
		s.fields[_n("preproxy_node")]:value(v.id, v.remark)
		s.fields[_n("to_node")]:value(v.id, v.remark)
	end
end

api.luci_types(arg[1], m, s, type_name, option_prefix)
