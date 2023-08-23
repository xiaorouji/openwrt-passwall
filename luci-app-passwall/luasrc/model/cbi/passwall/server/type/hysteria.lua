local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("hysteria") then
	return
end

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
	if self.option:find(option_prefix) == 1 then
		m:set(section, self.option:sub(1 + #option_prefix), value)
	end
end

-- [[ Hysteria ]]

s.fields["type"]:value("Hysteria", translate("Hysteria"))

o = s:option(Value, "hysteria_port", translate("Listen Port"))
o.datatype = "port"

o = s:option(ListValue, "hysteria_protocol", translate("Protocol"))
o:value("udp", "UDP")
o:value("faketcp", "faketcp")
o:value("wechat-video", "wechat-video")

o = s:option(Value, "hysteria_obfs", translate("Obfs Password"))
o.not_rewrite = true

o = s:option(ListValue, "hysteria_auth_type", translate("Auth Type"))
o:value("disable", translate("Disable"))
o:value("string", translate("STRING"))
o.not_rewrite = true

o = s:option(Value, "hysteria_auth_password", translate("Auth Password"))
o.password = true
o:depends({ hysteria_auth_type = "string" })
o.not_rewrite = true

o = s:option(Value, "hysteria_alpn", translate("QUIC TLS ALPN"))
o.not_rewrite = true

o = s:option(Flag, "hysteria_udp", translate("UDP"))
o.default = "1"
o.not_rewrite = true

o = s:option(Value, "hysteria_up_mbps", translate("Max upload Mbps"))
o.default = "10"
o.not_rewrite = true

o = s:option(Value, "hysteria_down_mbps", translate("Max download Mbps"))
o.default = "50"
o.not_rewrite = true

o = s:option(Value, "hysteria_recv_window_conn", translate("QUIC stream receive window"))
o.not_rewrite = true

o = s:option(Value, "hysteria_recv_window", translate("QUIC connection receive window"))
o.not_rewrite = true

o = s:option(Flag, "hysteria_disable_mtu_discovery", translate("Disable MTU detection"))
o.not_rewrite = true

o = s:option(Flag, "hysteria_tls", translate("TLS"))
o.default = 0
o.validate = function(self, value, t)
	if value then
		if value == "1" then
			local ca = s.fields["hysteria_tls_certificateFile"]:formvalue(t) or ""
			local key = s.fields["hysteria_tls_keyFile"]:formvalue(t) or ""
			if ca == "" or key == "" then
				return nil, translate("Public key and Private key path can not be empty!")
			end
		end
		return value
	end
end

o = s:option(FileUpload, "hysteria_tls_certificateFile", translate("Public key absolute path"), translate("as:") .. "/etc/ssl/fullchain.pem")
o.default = m:get(s.section, "tls_certificateFile") or "/etc/config/ssl/" .. arg[1] .. ".pem"
o:depends({ hysteria_tls = true })
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not nixio.fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end

o = s:option(FileUpload, "hysteria_tls_keyFile", translate("Private key absolute path"), translate("as:") .. "/etc/ssl/private.key")
o.default = m:get(s.section, "tls_keyFile") or "/etc/config/ssl/" .. arg[1] .. ".key"
o:depends({ hysteria_tls = true })
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not nixio.fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end

o = s:option(Flag, "hysteria_log", translate("Log"))
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
				deps[index]["type"] = "Hysteria"
			end
		else
			s.fields[key]:depends({ type = "Hysteria" })
		end
	end
end
