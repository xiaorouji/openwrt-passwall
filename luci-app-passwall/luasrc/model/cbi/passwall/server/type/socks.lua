local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("microsocks") then
	return
end

local type_name = "Socks"

local option_prefix = "socks_"

local function _n(name)
	return option_prefix .. name
end

-- [[ microsocks ]]

s.fields["type"]:value(type_name, "Socks")

o = s:option(Value, _n("port"), translate("Listen Port"))
o.datatype = "port"

o = s:option(Flag, _n("auth"), translate("Auth"))
o.validate = function(self, value, t)
	if value and value == "1" then
		local user_v = s.fields[_n("username")] and s.fields[_n("username")]:formvalue(t) or ""
		local pass_v = s.fields[_n("password")] and s.fields[_n("password")]:formvalue(t) or ""
		if user_v == "" or pass_v == "" then
			return nil, translate("Username and Password must be used together!")
		end
	end
	return value
end

o = s:option(Value, _n("username"), translate("Username"))
o:depends({ [_n("auth")] = true })

o = s:option(Value, _n("password"), translate("Password"))
o.password = true
o:depends({ [_n("auth")] = true })

o = s:option(Flag, _n("log"), translate("Log"))
o.default = "1"

api.luci_types(arg[1], m, s, type_name, option_prefix)
