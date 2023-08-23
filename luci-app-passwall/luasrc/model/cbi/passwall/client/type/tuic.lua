local m, s = ...

local api = require "luci.passwall.api"

if not api.is_finded("tuic-client") then
	return
end

local option_prefix = "tuic_"

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

-- [[ TUIC ]]

s.fields["type"]:value("TUIC", translate("TUIC"))

o = s:option(Value, "tuic_address", translate("Address (Support Domain Name)"))

o = s:option(Value, "tuic_port", translate("Port"))
o.datatype = "port"

o = s:option(Value, "tuic_uuid", translate("ID"))
o.password = true

-- Tuic Password for remote server connect
o = s:option(Value, "tuic_password", translate("TUIC User Password For Connect Remote Server"))
o.password = true
o.rmempty = true
o.default = ""
o.not_rewrite = true

--[[
-- Tuic username for local socks connect
o = s:option(Value, "tuic_socks_username", translate("TUIC UserName For Local Socks"))
o.rmempty = true
o.default = ""
o.not_rewrite = true

-- Tuic Password for local socks connect
o = s:option(Value, "tuic_socks_password", translate("TUIC Password For Local Socks"))
o.password = true
o.rmempty = true
o.default = ""
o.not_rewrite = true
--]]

o = s:option(Value, "tuic_ip", translate("Set the TUIC proxy server ip address"))
o.datatype = "ipaddr"
o.rmempty = true
o.not_rewrite = true

o = s:option(ListValue, "tuic_udp_relay_mode", translate("UDP relay mode"))
o:value("native", translate("native"))
o:value("quic", translate("QUIC"))
o.default = "native"
o.rmempty = true
o.not_rewrite = true

o = s:option(ListValue, "tuic_congestion_control", translate("Congestion control algorithm"))
o:value("bbr", translate("BBR"))
o:value("cubic", translate("CUBIC"))
o:value("new_reno", translate("New Reno"))
o.default = "cubic"
o.rmempty = true
o.not_rewrite = true

o = s:option(Value, "tuic_heartbeat", translate("Heartbeat interval(second)"))
o.datatype = "uinteger"
o.default = "3"
o.rmempty = true
o.not_rewrite = true

o = s:option(Value, "tuic_timeout", translate("Timeout for establishing a connection to server(second)"))
o.datatype = "uinteger"
o.default = "8"
o.rmempty = true
o.not_rewrite = true

o = s:option(Value, "tuic_gc_interval", translate("Garbage collection interval(second)"))
o.datatype = "uinteger"
o.default = "3"
o.rmempty = true
o.not_rewrite = true

o = s:option(Value, "tuic_gc_lifetime", translate("Garbage collection lifetime(second)"))
o.datatype = "uinteger"
o.default = "15"
o.rmempty = true
o.not_rewrite = true

o = s:option(Value, "tuic_send_window", translate("TUIC send window"))
o.datatype = "uinteger"
o.default = 20971520
o.rmempty = true
o.not_rewrite = true

o = s:option(Value, "tuic_receive_window", translate("TUIC receive window"))
o.datatype = "uinteger"
o.default = 10485760
o.rmempty = true
o.not_rewrite = true

o = s:option(Value, "tuic_max_package_size", translate("TUIC Maximum packet size the socks5 server can receive from external, in bytes"))
o.datatype = "uinteger"
o.default = 1500
o.rmempty = true
o.not_rewrite = true

--Tuic settings for the local inbound socks5 server
o = s:option(Flag, "tuic_dual_stack", translate("Set if the listening socket should be dual-stack"))
o.default = 0
o.rmempty = true
o.not_rewrite = true

o = s:option(Flag, "tuic_disable_sni", translate("Disable SNI"))
o.default = 0
o.rmempty = true
o.not_rewrite = true

o = s:option(Flag, "tuic_zero_rtt_handshake", translate("Enable 0-RTT QUIC handshake"))
o.default = 0
o.rmempty = true
o.not_rewrite = true

o = s:option(DynamicList, "tuic_tls_alpn", translate("TLS ALPN"))
o.rmempty = true
o.not_rewrite = true

for key, value in pairs(s.fields) do
	if key:find(option_prefix) == 1 then
		if not s.fields[key].not_rewrite then
			s.fields[key].cfgvalue = rm_prefix_cfgvalue
			s.fields[key].write = rm_prefix_write
		end

		local deps = s.fields[key].deps
		if #deps > 0 then
			for index, value in ipairs(deps) do
				deps[index]["type"] = "TUIC"
			end
		else
			s.fields[key]:depends({ type = "TUIC" })
		end
	end
end
