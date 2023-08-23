local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("ss-redir") then
	return
end

local option_prefix = "ss_"

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

local ss_encrypt_method_list = {
	"rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr",
	"aes-192-ctr", "aes-256-ctr", "bf-cfb", "salsa20", "chacha20", "chacha20-ietf",
	"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305"
}

-- [[ Shadowsocks Libev ]]

s.fields["type"]:value("SS", translate("Shadowsocks Libev"))

o = s:option(Value, "ss_address", translate("Address (Support Domain Name)"))

o = s:option(Value, "ss_port", translate("Port"))
o.datatype = "port"

o = s:option(Value, "ss_password", translate("Password"))
o.password = true

o = s:option(Value, "ss_method", translate("Encrypt Method"))
for a, t in ipairs(ss_encrypt_method_list) do o:value(t) end

o = s:option(Value, "ss_timeout", translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 300

o = s:option(ListValue, "ss_tcp_fast_open", "TCP " .. translate("Fast Open"), translate("Need node support required"))
o:value("false")
o:value("true")

o = s:option(ListValue, "ss_plugin", translate("plugin"))
o:value("none", translate("none"))
if api.is_finded("xray-plugin") then o:value("xray-plugin") end
if api.is_finded("v2ray-plugin") then o:value("v2ray-plugin") end
if api.is_finded("obfs-local") then o:value("obfs-local") end

o = s:option(Value, "ss_plugin_opts", translate("opts"))
o:depends({ ss_plugin = "xray-plugin"})
o:depends({ ss_plugin = "v2ray-plugin"})
o:depends({ ss_plugin = "obfs-local"})

for key, value in pairs(s.fields) do
	if key:find(option_prefix) == 1 then
		if not s.fields[key].not_rewrite then
			s.fields[key].cfgvalue = rm_prefix_cfgvalue
			s.fields[key].write = rm_prefix_write
		end

		local deps = s.fields[key].deps
		if #deps > 0 then
			for index, value in ipairs(deps) do
				deps[index]["type"] = "SS"
			end
		else
			s.fields[key]:depends({ type = "SS" })
		end
	end
end
