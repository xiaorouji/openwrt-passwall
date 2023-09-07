local m, s = ...

local api = require "luci.passwall.api"

if not api.finded_com("hysteria") then
	return
end

local type_name = "Hysteria"

local option_prefix = "hysteria_"

local function option_name(name)
	return option_prefix .. name
end

-- [[ Hysteria ]]

s.fields["type"]:value(type_name, translate("Hysteria"))

o = s:option(ListValue, option_name("protocol"), translate("Protocol"))
o:value("udp", "UDP")
o:value("faketcp", "faketcp")
o:value("wechat-video", "wechat-video")

o = s:option(Value, option_name("address"), translate("Address (Support Domain Name)"))

o = s:option(Value, option_name("port"), translate("Port"))
o.datatype = "port"

o = s:option(Value, option_name("hop"), translate("Additional ports for hysteria hop"))
o.rewrite_option = o.option

o = s:option(Value, option_name("obfs"), translate("Obfs Password"))
o.rewrite_option = o.option

o = s:option(ListValue, option_name("auth_type"), translate("Auth Type"))
o:value("disable", translate("Disable"))
o:value("string", translate("STRING"))
o:value("base64", translate("BASE64"))
o.rewrite_option = o.option

o = s:option(Value, option_name("auth_password"), translate("Auth Password"))
o.password = true
o:depends({ [option_name("auth_type")] = "string"})
o:depends({ [option_name("auth_type")] = "base64"})
o.rewrite_option = o.option

o = s:option(Value, option_name("alpn"), translate("QUIC TLS ALPN"))
o.rewrite_option = o.option

o = s:option(Flag, option_name("fast_open"), translate("Fast Open"))
o.default = "0"

o = s:option(Value, option_name("tls_serverName"), translate("Domain"))

o = s:option(Flag, option_name("tls_allowInsecure"), translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"

o = s:option(Value, option_name("up_mbps"), translate("Max upload Mbps"))
o.default = "10"
o.rewrite_option = o.option

o = s:option(Value, option_name("down_mbps"), translate("Max download Mbps"))
o.default = "50"
o.rewrite_option = o.option

o = s:option(Value, option_name("recv_window_conn"), translate("QUIC stream receive window"))
o.rewrite_option = o.option

o = s:option(Value, option_name("recv_window"), translate("QUIC connection receive window"))
o.rewrite_option = o.option

o = s:option(Value, option_name("handshake_timeout"), translate("Handshake Timeout"))
o.rewrite_option = o.option

o = s:option(Value, option_name("idle_timeout"), translate("Idle Timeout"))
o.rewrite_option = o.option

o = s:option(Value, option_name("hop_interval"), translate("Hop Interval"))
o.rewrite_option = o.option

o = s:option(Flag, option_name("disable_mtu_discovery"), translate("Disable MTU detection"))
o.rewrite_option = o.option

o = s:option(Flag, option_name("lazy_start"), translate("Lazy Start"))
o.rewrite_option = o.option

api.luci_types(arg[1], m, s, type_name, option_prefix)
