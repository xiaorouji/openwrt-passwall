local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("hysteria") then
	return
end

local type_name = "Hysteria"

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
	if s.fields["type"]:formvalue(arg[1]) == type_name then
		if self.option:find(option_prefix) == 1 then
			m:set(section, self.option:sub(1 + #option_prefix), value)
		end
	end
end
local function rm_prefix_remove(self, section, value)
	if s.fields["type"]:formvalue(arg[1]) == type_name then
		if self.option:find(option_prefix) == 1 then
			m:del(section, self.option:sub(1 + #option_prefix))
		end
	end
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
o.not_rewrite = true

o = s:option(Value, option_name("obfs"), translate("Obfs Password"))
o.not_rewrite = true

o = s:option(ListValue, option_name("auth_type"), translate("Auth Type"))
o:value("disable", translate("Disable"))
o:value("string", translate("STRING"))
o:value("base64", translate("BASE64"))
o.not_rewrite = true

o = s:option(Value, option_name("auth_password"), translate("Auth Password"))
o.password = true
o:depends({ [option_name("auth_type")] = "string"})
o:depends({ [option_name("auth_type")] = "base64"})
o.not_rewrite = true

o = s:option(Value, option_name("alpn"), translate("QUIC TLS ALPN"))
o.not_rewrite = true

o = s:option(Flag, option_name("fast_open"), translate("Fast Open"))
o.default = "0"

o = s:option(Value, option_name("tls_serverName"), translate("Domain"))

o = s:option(Flag, option_name("tls_allowInsecure"), translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"

o = s:option(Value, option_name("up_mbps"), translate("Max upload Mbps"))
o.default = "10"
o.not_rewrite = true

o = s:option(Value, option_name("down_mbps"), translate("Max download Mbps"))
o.default = "50"
o.not_rewrite = true

o = s:option(Value, option_name("recv_window_conn"), translate("QUIC stream receive window"))
o.not_rewrite = true

o = s:option(Value, option_name("recv_window"), translate("QUIC connection receive window"))
o.not_rewrite = true

o = s:option(Value, option_name("handshake_timeout"), translate("Handshake Timeout"))
o.not_rewrite = true

o = s:option(Value, option_name("idle_timeout"), translate("Idle Timeout"))
o.not_rewrite = true

o = s:option(Value, option_name("hop_interval"), translate("Hop Interval"))
o.not_rewrite = true

o = s:option(Flag, option_name("disable_mtu_discovery"), translate("Disable MTU detection"))
o.not_rewrite = true

o = s:option(Flag, option_name("lazy_start"), translate("Lazy Start"))
o.not_rewrite = true

for key, value in pairs(s.fields) do
	if key:find(option_prefix) == 1 then
		if not s.fields[key].not_rewrite then
			s.fields[key].cfgvalue = rm_prefix_cfgvalue
			s.fields[key].write = rm_prefix_write
			s.fields[key].remove = rm_prefix_remove
		end

		local deps = s.fields[key].deps
		if #deps > 0 then
			for index, value in ipairs(deps) do
				deps[index]["type"] = type_name
			end
		else
			s.fields[key]:depends({ type = type_name })
		end
	end
end
