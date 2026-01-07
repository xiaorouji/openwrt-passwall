local api = require "luci.passwall.api"
local appname = "passwall"

m = Map(appname)
m.redirect = api.url()
api.set_apply_on_parse(m)

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

m:append(Template(appname .. "/cbi/nodes_multivalue_com"))
m:append(Template(appname .. "/cbi/nodes_listvalue_com"))

local has_singbox = api.finded_com("sing-box")
local has_xray = api.finded_com("xray")

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	nodes_table[#nodes_table + 1] = e
end

s = m:section(NamedSection, arg[1], translate("Socks Config"), translate("Socks Config"))
s.addremove = false
s.dynamic = false

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

local auto_switch_tip
local current_node = api.get_cache_var("socks_" .. arg[1])
if current_node then
	local n = m:get(current_node)
	if n then
		if tonumber(m:get(arg[1], "enable_autoswitch") or 0) == 1 then
			if n then
				local remarks = api.get_node_remarks(n)
				local url = api.url("node_config", n[".name"])
				auto_switch_tip = translatef("Current node: %s", string.format('<a href="%s">%s</a>', url, remarks)) .. "<br />"
			end
		end
	end
end

socks_node = s:option(ListValue, "node", translate("Node"))
if auto_switch_tip then
	socks_node.description = auto_switch_tip
end
socks_node.template = appname .. "/cbi/nodes_listvalue"
socks_node.group = {}

o = s:option(Flag, "bind_local", translate("Bind Local"), translate("When selected, it can only be accessed localhost."))
o.default = "0"

local n = 1
m.uci:foreach(appname, "socks", function(s)
	if s[".name"] == section then
		return false
	end
	n = n + 1
end)

o = s:option(Value, "port", "Socks " .. translate("Listen Port"))
o.default = n + 1080
o.datatype = "port"
o.rmempty = false

if has_singbox or has_xray then
	o = s:option(Value, "http_port", "HTTP " .. translate("Listen Port") .. " " .. translate("0 is not use"))
	o.default = 0
	o.datatype = "port"
end

o = s:option(Flag, "log", translate("Enable") .. " " .. translate("Log"))
o.default = 1
o.rmempty = false

o = s:option(Flag, "enable_autoswitch", translate("Auto Switch"))
o.default = 0
o.rmempty = false

o = s:option(Value, "autoswitch_testing_time", translate("How often to test"), translate("Units:seconds"))
o.datatype = "min(10)"
o.default = 30
o:depends("enable_autoswitch", true)

o = s:option(Value, "autoswitch_connect_timeout", translate("Timeout seconds"), translate("Units:seconds"))
o.datatype = "min(1)"
o.default = 3
o:depends("enable_autoswitch", true)

o = s:option(Value, "autoswitch_retry_num", translate("Timeout retry num"))
o.datatype = "min(1)"
o.default = 1
o:depends("enable_autoswitch", true)
	
o = s:option(MultiValue, "autoswitch_backup_node", translate("List of backup nodes"))
o:depends("enable_autoswitch", true)
o.widget = "checkbox"
o.template = appname .. "/cbi/nodes_multivalue"
o.group = {}
for i, v in pairs(nodes_table) do
	o:value(v.id, v.remark)
	o.group[#o.group+1] = v.group or ""
	socks_node:value(v.id, v["remark"])
	socks_node.group[#socks_node.group+1] = (v.group and v.group ~= "") and v.group or translate("default")
end
-- 读取旧 DynamicList
function o.cfgvalue(self, section)
	return m.uci:get_list(appname, section, "autoswitch_backup_node") or {}
end
-- 写入保持 DynamicList
function o.write(self, section, value)
	local old = m.uci:get_list(appname, section, "autoswitch_backup_node") or {}
	local new, set = {}, {}
	for v in value:gmatch("%S+") do
		new[#new + 1] = v
		set[v] = 1
	end
	for _, v in ipairs(old) do
		if not set[v] then
			m.uci:set_list(appname, section, "autoswitch_backup_node", new)
			return
		end
		set[v] = nil
	end
	for _ in pairs(set) do
		m.uci:set_list(appname, section, "autoswitch_backup_node", new)
		return
	end
end

o = s:option(Flag, "autoswitch_restore_switch", translate("Restore Switch"), translate("When detects main node is available, switch back to the main node."))
o:depends("enable_autoswitch", true)

o = s:option(Value, "autoswitch_probe_url", translate("Probe URL"), translate("The URL used to detect the connection status."))
o:value("https://cp.cloudflare.com/", "Cloudflare")
o:value("https://www.gstatic.com/generate_204", "Gstatic")
o:value("https://www.google.com/generate_204", "Google")
o:value("https://www.youtube.com/generate_204", "YouTube")
o:value("https://connect.rom.miui.com/generate_204", "MIUI (CN)")
o:value("https://connectivitycheck.platform.hicloud.com/generate_204", "HiCloud (CN)")
o.default = o.keylist[3]
o:depends("enable_autoswitch", true)

o = s:option(DummyValue, "btn")
o.template = appname .. "/socks_auto_switch/btn"
o:depends("enable_autoswitch", true)

return m
