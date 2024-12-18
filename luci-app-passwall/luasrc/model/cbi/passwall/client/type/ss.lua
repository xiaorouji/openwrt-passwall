local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("ss-local") and not api.is_finded("ss-redir") then
	return
end

local type_name = "SS"

local option_prefix = "ss_"

local function _n(name)
	return option_prefix .. name
end

local ss_encrypt_method_list = {
	"rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr",
	"aes-192-ctr", "aes-256-ctr", "bf-cfb", "salsa20", "chacha20", "chacha20-ietf",
	"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305"
}

-- [[ Shadowsocks Libev ]]

s.fields["type"]:value(type_name, translate("Shadowsocks Libev"))

o = s:option(Value, _n("address"), translate("Address (Support Domain Name)"))

o = s:option(Value, _n("port"), translate("Port"))
o.datatype = "port"

o = s:option(Value, _n("password"), translate("Password"))
o.password = true

o = s:option(Value, _n("method"), translate("Encrypt Method"))
for a, t in ipairs(ss_encrypt_method_list) do o:value(t) end

o = s:option(Value, _n("timeout"), translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 300

o = s:option(ListValue, _n("tcp_fast_open"), "TCP " .. translate("Fast Open"), translate("Need node support required"))
o:value("false")
o:value("true")

o = s:option(ListValue, _n("plugin"), translate("plugin"))
o:value("none", translate("none"))
if api.is_finded("xray-plugin") then o:value("xray-plugin") end
if api.is_finded("v2ray-plugin") then o:value("v2ray-plugin") end
if api.is_finded("obfs-local") then o:value("obfs-local") end

o = s:option(Value, _n("plugin_opts"), translate("opts"))
o:depends({ [_n("plugin")] = "xray-plugin"})
o:depends({ [_n("plugin")] = "v2ray-plugin"})
o:depends({ [_n("plugin")] = "obfs-local"})

api.luci_types(arg[1], m, s, type_name, option_prefix)
