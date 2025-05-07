local m, s = ...

local api = require "luci.passwall.api"

if not api.finded_com("hysteria") then
	return
end

local fs = api.fs

local type_name = "Hysteria2"

local option_prefix = "hysteria2_"

local function _n(name)
	return option_prefix .. name
end

-- [[ Hysteria2 ]]

s.fields["type"]:value(type_name, "Hysteria2")

o = s:option(Flag, _n("custom"), translate("Use Custom Config"))

o = s:option(Value, _n("port"), translate("Listen Port"))
o.datatype = "port"
o:depends({ [_n("custom")] = false })

o = s:option(Value, _n("obfs"), translate("Obfs Password"))
o.rewrite_option = o.option
o:depends({ [_n("custom")] = false })

o = s:option(Value, _n("auth_password"), translate("Auth Password"))
o.password = true
o.rewrite_option = o.option
o:depends({ [_n("custom")] = false })

o = s:option(Flag, _n("udp"), translate("UDP"))
o.default = "1"
o.rewrite_option = o.option
o:depends({ [_n("custom")] = false })

o = s:option(Value, _n("up_mbps"), translate("Max upload Mbps"))
o.rewrite_option = o.option
o:depends({ [_n("custom")] = false })

o = s:option(Value, _n("down_mbps"), translate("Max download Mbps"))
o.rewrite_option = o.option
o:depends({ [_n("custom")] = false })

o = s:option(Flag, _n("ignoreClientBandwidth"), translate("ignoreClientBandwidth"))
o.default = "0"
o.rewrite_option = o.option
o:depends({ [_n("custom")] = false })

o = s:option(FileUpload, _n("tls_certificateFile"), translate("Public key absolute path"), translate("as:") .. "/etc/ssl/fullchain.pem")
o.default = m:get(s.section, "tls_certificateFile") or "/etc/config/ssl/" .. arg[1] .. ".pem"
if o and o:formvalue(arg[1]) then o.default = o:formvalue(arg[1]) end
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end
o:depends({ [_n("custom")] = false })

o = s:option(FileUpload, _n("tls_keyFile"), translate("Private key absolute path"), translate("as:") .. "/etc/ssl/private.key")
o.default = m:get(s.section, "tls_keyFile") or "/etc/config/ssl/" .. arg[1] .. ".key"
if o and o:formvalue(arg[1]) then o.default = o:formvalue(arg[1]) end
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end
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
