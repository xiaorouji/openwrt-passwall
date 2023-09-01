local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("microsocks") then
	return
end

local type_name = "Socks"

local option_prefix = "socks_"

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

-- [[ microsocks ]]

s.fields["type"]:value(type_name, "Socks")

o = s:option(Value, option_name("port"), translate("Listen Port"))
o.datatype = "port"

o = s:option(Flag, option_name("auth"), translate("Auth"))
o.validate = function(self, value, t)
	if value and value == "1" then
		local user_v = s.fields[option_name("username")]:formvalue(t) or ""
		local pass_v = s.fields[option_name("password")]:formvalue(t) or ""
		if user_v == "" or pass_v == "" then
			return nil, translate("Username and Password must be used together!")
		end
	end
	return value
end

o = s:option(Value, option_name("username"), translate("Username"))
o:depends({ [option_name("auth")] = true })

o = s:option(Value, option_name("password"), translate("Password"))
o.password = true
o:depends({ [option_name("auth")] = true })

o = s:option(Flag, option_name("log"), translate("Log"))
o.default = "1"

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
