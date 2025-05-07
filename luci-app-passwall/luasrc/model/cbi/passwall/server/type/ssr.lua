local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("ssr-server") then
	return
end

local type_name = "SSR"

local option_prefix = "ssr_"

local function _n(name)
	return option_prefix .. name
end

local ssr_encrypt_method_list = {
	"none", "table", "rc2-cfb", "rc4", "rc4-md5", "rc4-md5-6", "aes-128-cfb",
	"aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
	"bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
	"cast5-cfb", "des-cfb", "idea-cfb", "seed-cfb", "salsa20", "chacha20",
	"chacha20-ietf"
}

local ssr_protocol_list = {
	"origin", "verify_simple", "verify_deflate", "verify_sha1", "auth_simple",
	"auth_sha1", "auth_sha1_v2", "auth_sha1_v4", "auth_aes128_md5",
	"auth_aes128_sha1", "auth_chain_a", "auth_chain_b", "auth_chain_c",
	"auth_chain_d", "auth_chain_e", "auth_chain_f"
}
local ssr_obfs_list = {
	"plain", "http_simple", "http_post", "random_head", "tls_simple",
	"tls1.0_session_auth", "tls1.2_ticket_auth"
}

-- [[ ShadowsocksR ]]

s.fields["type"]:value(type_name, translate("ShadowsocksR"))

o = s:option(Flag, _n("custom"), translate("Use Custom Config"))

o = s:option(Value, _n("port"), translate("Listen Port"))
o.datatype = "port"
o:depends({ [_n("custom")] = false })

o = s:option(Value, _n("password"), translate("Password"))
o.password = true
o:depends({ [_n("custom")] = false })

o = s:option(ListValue, _n("method"), translate("Encrypt Method"))
for a, t in ipairs(ssr_encrypt_method_list) do o:value(t) end
o:depends({ [_n("custom")] = false })

o = s:option(ListValue, _n("protocol"), translate("Protocol"))
for a, t in ipairs(ssr_protocol_list) do o:value(t) end
o:depends({ [_n("custom")] = false })

o = s:option(Value, _n("protocol_param"), translate("Protocol_param"))
o:depends({ [_n("custom")] = false })

o = s:option(ListValue, _n("obfs"), translate("Obfs"))
for a, t in ipairs(ssr_obfs_list) do o:value(t) end
o:depends({ [_n("custom")] = false })

o = s:option(Value, _n("obfs_param"), translate("Obfs_param"))
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

o = s:option(Flag, _n("udp_forward"), translate("UDP Forward"))
o.default = "1"
o.rmempty = false

o = s:option(Flag, _n("log"), translate("Log"))
o.default = "1"
o.rmempty = false

api.luci_types(arg[1], m, s, type_name, option_prefix)
