local api = require "luci.passwall.api"
local appname = "passwall"
local datatypes = api.datatypes
local net = require "luci.model.network".init()

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = {
			id = e[".name"],
			obj = e,
			remarks = e["remark"]
		}
	end
end

m = Map(appname)
api.set_apply_on_parse(m)

-- [[ Haproxy Settings ]]--
s = m:section(TypedSection, "global_haproxy", translate("Basic Settings"))
s.anonymous = true

s:append(Template(appname .. "/haproxy/status"))

---- Balancing Enable
o = s:option(Flag, "balancing_enable", translate("Enable Load Balancing"))
o.rmempty = false
o.default = false

---- Console Login Auth
o = s:option(Flag, "console_auth", translate("Console Login Auth"))
o.default = false
o:depends("balancing_enable", true)

---- Console Username
o = s:option(Value, "console_user", translate("Console Username"))
o.default = ""
o:depends("console_auth", true)

---- Console Password
o = s:option(Value, "console_password", translate("Console Password"))
o.password = true
o.default = ""
o:depends("console_auth", true)

---- Console Port
o = s:option(Value, "console_port", translate("Console Port"), translate(
				 "In the browser input routing IP plus port access, such as:192.168.1.1:1188"))
o.default = "1188"
o:depends("balancing_enable", true)

o = s:option(Flag, "bind_local", translate("Haproxy Port") .. " " .. translate("Bind Local"), translate("When selected, it can only be accessed localhost."))
o.default = "0"
o:depends("balancing_enable", true)

---- Health Check Type
o = s:option(ListValue, "health_check_type", translate("Health Check Type"))
o.default = "passwall_logic"
o:value("tcp", "TCP")
o:value("passwall_logic", translate("URL Test") .. string.format("(passwall %s)", translate("Inner implement")))
o:depends("balancing_enable", true)

---- Passwall Inner implement Probe URL
o = s:option(Value, "health_probe_url", translate("Probe URL"))
o.default = "https://www.google.com/generate_204"
o:value("https://cp.cloudflare.com/", "Cloudflare")
o:value("https://www.gstatic.com/generate_204", "Gstatic")
o:value("https://www.google.com/generate_204", "Google")
o:value("https://www.youtube.com/generate_204", "YouTube")
o:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
o:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
o.description = translate("The URL used to detect the connection status.")
o:depends("health_check_type", "passwall_logic")

---- Health Check Inter
o = s:option(Value, "health_check_inter", translate("Health Check Inter"), translate("Units:seconds"))
o.default = "60"
o:depends("balancing_enable", true)

o = s:option(DummyValue, "health_check_tips", " ")
o.rawhtml = true
o.cfgvalue = function(t, n)
	return string.format('<span style="color: red">%s</span>', translate("When the URL test is used, the load balancing node will be converted into a Socks node. when node list set customizing, must be a Socks node, otherwise the health check will be invalid."))
end
o:depends("health_check_type", "passwall_logic")

-- [[ Balancing Settings ]]--
s = m:section(TypedSection, "haproxy_config", translate("Node List"),
			  "<font color='red'>" ..
			  translate("Add a node, Export Of Multi WAN Only support Multi Wan. Load specific gravity range 1-256. Multiple primary servers can be load balanced, standby will only be enabled when the primary server is offline! Multiple groups can be set, Haproxy port same one for each group.") ..
			  "\n" .. translate("Note that the node configuration parameters for load balancing must be consistent when use TCP health check type, otherwise it cannot be used normally!") ..
			  "</font>")
s.template = "cbi/tblsection"
s.sortable = true
s.anonymous = true
s.addremove = true

s.create = function(e, t)
	TypedSection.create(e, api.gen_short_uuid())
end

s.remove = function(self, section)
	for k, v in pairs(self.children) do
		v.rmempty = true
		v.validate = nil
	end
	TypedSection.remove(self, section)
end

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Node Address
o = s:option(Value, "lbss", translate("Node Address"))
for k, v in pairs(nodes_table) do o:value(v.id, v.remarks) end
o.rmempty = false
o.validate = function(self, value)
	if not value then return nil end
	local t = m:get(value) or nil
	if t and t[".type"] == "nodes" then
		return value
	end
	if datatypes.hostport(value) or datatypes.ip4addrport(value) then
		return value
	end
	if api.is_ipv6addrport(value) then
		return value
	end
	return nil, value
end

---- Haproxy Port
o = s:option(Value, "haproxy_port", translate("Haproxy Port"))
o.datatype = "port"
o.default = 1181
o.rmempty = false

---- Node Weight
o = s:option(Value, "lbweight", translate("Node Weight"))
o.datatype = "uinteger"
o.default = 5
o.rmempty = false

---- Export
o = s:option(ListValue, "export", translate("Export Of Multi WAN"))
o:value(0, translate("Auto"))
local wa = require "luci.tools.webadmin"
wa.cbi_add_networks(o)
o.default = 0
o.rmempty = false

---- Mode
o = s:option(ListValue, "backup", translate("Mode"))
o:value(0, translate("Primary"))
o:value(1, translate("Standby"))
o.rmempty = false

return m
