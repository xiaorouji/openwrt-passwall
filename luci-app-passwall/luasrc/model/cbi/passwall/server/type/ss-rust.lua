local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("ssserver") then
	return
end

local type_name = "SS-Rust"

local option_prefix = "ssrust_"

local function _n(name)
	return option_prefix .. name
end

local ssrust_encrypt_method_list = {
	"plain", "none",
	"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

-- [[ Shadowsocks Rust ]]

s.fields["type"]:value(type_name, translate("Shadowsocks Rust"))

o = s:option(Flag, _n("custom"), translate("Use Custom Config"))

o = s:option(Value, _n("port"), translate("Listen Port"))
o.datatype = "port"
o:depends({ [_n("custom")] = false })

o = s:option(Value, _n("password"), translate("Password"))
o.password = true
o:depends({ [_n("custom")] = false })

o = s:option(ListValue, _n("method"), translate("Encrypt Method"))
for a, t in ipairs(ssrust_encrypt_method_list) do o:value(t) end
o:depends({ [_n("custom")] = false })

o = s:option(Value, _n("timeout"), translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 300
o:depends({ [_n("custom")] = false })

o = s:option(Flag, _n("tcp_fast_open"), "TCP " .. translate("Fast Open"))
o.default = "0"
o:depends({ [_n("custom")] = false })

o = s:option(TextValue, _n("custom_config"), translate("Custom Config"))
o.rows = 10
o.wrap = "off"
o:depends({ [_n("custom")] = true })
o.validate = function(self, value, t)
	if value and api.jsonc.parse(value) then
		return value
	else
		return nil, translate("Must be JSON text!")
	end
end
o.custom_cfgvalue = function(self, section, value)
	local config_str = m:get(section, "config_str")
	if config_str then
		return api.base64Decode(config_str)
	end
end
o.custom_write = function(self, section, value)
	m:set(section, "config_str", api.base64Encode(value))
end

o = s:option(Flag, _n("log"), translate("Log"))
o.default = "1"
o.rmempty = false

api.luci_types(arg[1], m, s, type_name, option_prefix)
