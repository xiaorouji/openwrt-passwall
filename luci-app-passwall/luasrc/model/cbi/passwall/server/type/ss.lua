local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("ss-server") then
	return
end

local type_name = "SS"

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

local ss_encrypt_method_list = {
	"rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr",
	"aes-192-ctr", "aes-256-ctr", "bf-cfb", "camellia-128-cfb",
	"camellia-192-cfb", "camellia-256-cfb", "salsa20", "chacha20",
	"chacha20-ietf", -- aead
	"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305"
}

-- [[ Shadowsocks ]]

s.fields["type"]:value(type_name, translate("Shadowsocks"))

o = s:option(Value, option_name("port"), translate("Listen Port"))
o.datatype = "port"

o = s:option(Value, option_name("password"), translate("Password"))
o.password = true

o = s:option(ListValue, option_name("method"), translate("Encrypt Method"))
for a, t in ipairs(ss_encrypt_method_list) do o:value(t) end

o = s:option(Value, option_name("timeout"), translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 300

o = s:option(Flag, option_name("tcp_fast_open"), "TCP " .. translate("Fast Open"))
o.default = "0"

o = s:option(Flag, option_name("log"), translate("Log"))
o.default = "1"
o.rmempty = false

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
