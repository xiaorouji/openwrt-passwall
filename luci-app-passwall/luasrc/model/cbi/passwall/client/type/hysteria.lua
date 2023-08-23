local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("hysteria") then
	return
end

local option_prefix = "hysteria_"

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

-- [[ Hysteria ]]

s.fields["type"]:value("Hysteria", translate("Hysteria"))

o = s:option(ListValue, "hysteria_protocol", translate("Protocol"))
o:value("udp", "UDP")
o:value("faketcp", "faketcp")
o:value("wechat-video", "wechat-video")

o = s:option(Value, "hysteria_address", translate("Address (Support Domain Name)"))

o = s:option(Value, "hysteria_port", translate("Port"))
o.datatype = "port"

o = s:option(Value, "hysteria_hop", translate("Additional ports for hysteria hop"))
o:depends("type", "Hysteria")
o.not_rewrite = true

o = s:option(Value, "hysteria_obfs", translate("Obfs Password"))
o.not_rewrite = true

o = s:option(ListValue, "hysteria_auth_type", translate("Auth Type"))
o:value("disable", translate("Disable"))
o:value("string", translate("STRING"))
o:value("base64", translate("BASE64"))
o.not_rewrite = true

o = s:option(Value, "hysteria_auth_password", translate("Auth Password"))
o.password = true
o:depends({ hysteria_auth_type = "string"})
o:depends({ hysteria_auth_type = "base64"})
o.not_rewrite = true

o = s:option(Value, "hysteria_alpn", translate("QUIC TLS ALPN"))
o.not_rewrite = true

o = s:option(Flag, "hysteria_fast_open", translate("Fast Open"))
o.default = "0"

o = s:option(Value, "hysteria_tls_serverName", translate("Domain"))

o = s:option(Flag, "hysteria_tls_allowInsecure", translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"

o = s:option(Value, "hysteria_up_mbps", translate("Max upload Mbps"))
o.default = "10"
o.not_rewrite = true

o = s:option(Value, "hysteria_down_mbps", translate("Max download Mbps"))
o.default = "50"
o.not_rewrite = true

o = s:option(Value, "hysteria_recv_window_conn", translate("QUIC stream receive window"))
o.not_rewrite = true

o = s:option(Value, "hysteria_recv_window", translate("QUIC connection receive window"))
o.not_rewrite = true

o = s:option(Value, "hysteria_handshake_timeout", translate("Handshake Timeout"))
o.not_rewrite = true

o = s:option(Value, "hysteria_idle_timeout", translate("Idle Timeout"))
o.not_rewrite = true

o = s:option(Value, "hysteria_hop_interval", translate("Hop Interval"))
o.not_rewrite = true

o = s:option(Flag, "hysteria_disable_mtu_discovery", translate("Disable MTU detection"))
o.not_rewrite = true

o = s:option(Flag, "hysteria_lazy_start", translate("Lazy Start"))
o.not_rewrite = true

for key, value in pairs(s.fields) do
	if key:find(option_prefix) == 1 then
		if not s.fields[key].not_rewrite then
			s.fields[key].cfgvalue = rm_prefix_cfgvalue
			s.fields[key].write = rm_prefix_write
		end

		local deps = s.fields[key].deps
		if #deps > 0 then
			for index, value in ipairs(deps) do
				deps[index]["type"] = "Hysteria"
			end
		else
			s.fields[key]:depends({ type = "Hysteria" })
		end
	end
end
