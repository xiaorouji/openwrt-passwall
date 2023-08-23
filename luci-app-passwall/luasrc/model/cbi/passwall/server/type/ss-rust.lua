local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("ssserver") then
	return
end

local option_prefix = "ssrust_"

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

local ssrust_encrypt_method_list = {
	"plain", "none",
	"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha8-poly1305", "2022-blake3-chacha20-poly1305"
}

-- [[ Shadowsocks Rust ]]

s.fields["type"]:value("SS-Rust", translate("Shadowsocks Rust"))

o = s:option(Value, "ssrust_port", translate("Listen Port"))
o.datatype = "port"

o = s:option(Value, "ssrust_password", translate("Password"))
o.password = true

o = s:option(ListValue, "ssrust_method", translate("Encrypt Method"))
for a, t in ipairs(ssrust_encrypt_method_list) do o:value(t) end

o = s:option(Value, "ssrust_timeout", translate("Connection Timeout"))
o.datatype = "uinteger"
o.default = 300

o = s:option(Flag, "ssrust_tcp_fast_open", "TCP " .. translate("Fast Open"))
o.default = "0"

o = s:option(Flag, "ssrust_log", translate("Log"))
o.default = "1"

for key, value in pairs(s.fields) do
	if key:find(option_prefix) == 1 then
		if not s.fields[key].not_rewrite then
			s.fields[key].cfgvalue = rm_prefix_cfgvalue
			s.fields[key].write = rm_prefix_write
		end

		local deps = s.fields[key].deps
		if #deps > 0 then
			for index, value in ipairs(deps) do
				deps[index]["type"] = "SS-Rust"
			end
		else
			s.fields[key]:depends({ type = "SS-Rust" })
		end
	end
end
