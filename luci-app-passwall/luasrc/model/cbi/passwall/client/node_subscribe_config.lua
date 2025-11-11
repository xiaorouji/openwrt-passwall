local api = require "luci.passwall.api"
local uci = api.uci
local appname = "passwall"

m = Map(appname)
m.redirect = api.url("node_subscribe")

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

function m.commit_handler(self)
	self:del(arg[1], "md5")
end

if api.is_js_luci() then
	m.apply_on_parse = false
	m.on_after_apply = function(self)
		uci:delete(appname, arg[1], "md5")
		uci:commit(appname)
		api.showMsg_Redirect(self.redirect, 3000)
	end
end

m.render = function(self, ...)
	Map.render(self, ...)
	api.optimize_cbi_ui()
end

local has_ss = api.is_finded("ss-redir")
local has_ss_rust = api.is_finded("sslocal")
local has_trojan_plus = api.is_finded("trojan-plus")
local has_singbox = api.finded_com("sing-box")
local has_xray = api.finded_com("xray")
local has_hysteria2 = api.finded_com("hysteria")
local ss_type = {}
local trojan_type = {}
local vmess_type = {}
local vless_type = {}
local hysteria2_type = {}
if has_ss then
	local s = "shadowsocks-libev"
	table.insert(ss_type, s)
end
if has_ss_rust then
	local s = "shadowsocks-rust"
	table.insert(ss_type, s)
end
if has_trojan_plus then
	local s = "trojan-plus"
	table.insert(trojan_type, s)
end
if has_singbox then
	local s = "sing-box"
	table.insert(trojan_type, s)
	table.insert(ss_type, s)
	table.insert(vmess_type, s)
	table.insert(vless_type, s)
	table.insert(hysteria2_type, s)
end
if has_xray then
	local s = "xray"
	table.insert(trojan_type, s)
	table.insert(ss_type, s)
	table.insert(vmess_type, s)
	table.insert(vless_type, s)
end
if has_hysteria2 then
	local s = "hysteria2"
	table.insert(hysteria2_type, s)
end
local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = {
			id = e[".name"],
			remark = e["remark"],
			type = e["type"],
			add_mode = e["add_mode"],
			chain_proxy = e["chain_proxy"]
		}
	end
end

s = m:section(NamedSection, arg[1])
s.addremove = false
s.dynamic = false

o = s:option(Value, "remark", translate("Subscribe Remark"))
o.rmempty = false
o.validate = function(self, value, section)
	value = api.trim(value)
	if value == "" then
		return nil, translate("Remark cannot be empty.")
	end
	local duplicate = false
	m.uci:foreach(appname, "subscribe_list", function(e)
		if e[".name"] ~= section and e["remark"] and e["remark"]:lower() == value:lower() then
			duplicate = true
			return false
		end
	end)
	if duplicate or value:lower() == "default" then
		return nil, translate("This remark already exists, please change a new remark.")
	end
	return value
end
o.write = function(self, section, value)
	local old = m:get(section, self.option) or ""
	if old:lower() ~= value:lower() then
		m.uci:foreach(appname, "nodes", function(e)
			if e["group"] and e["group"]:lower() == old:lower() then
				m.uci:set(appname, e[".name"], "group", value)
			end
		end)
	end
	return Value.write(self, section, value)
end

o = s:option(TextValue, "url", translate("Subscribe URL"))
o.rows = 5
o.rmempty = false
o.validate = function(self, value)
	if not value or value == "" then
		return nil, translate("URL cannot be empty.")
	end
	return value:gsub("%s+", ""):gsub("%z", "")
end

o = s:option(Flag, "allowInsecure", translate("allowInsecure"), translate("Whether unsafe connections are allowed. When checked, Certificate validation will be skipped."))
o.default = "0"
o.rmempty = false

o = s:option(ListValue, "filter_keyword_mode", translate("Filter keyword Mode"))
o.default = "5"
o:value("0", translate("Close"))
o:value("1", translate("Discard List"))
o:value("2", translate("Keep List"))
o:value("3", translate("Discard List,But Keep List First"))
o:value("4", translate("Keep List,But Discard List First"))
o:value("5", translate("Use global config"))

o = s:option(DynamicList, "filter_discard_list", translate("Discard List"))
o:depends("filter_keyword_mode", "1")
o:depends("filter_keyword_mode", "3")
o:depends("filter_keyword_mode", "4")

o = s:option(DynamicList, "filter_keep_list", translate("Keep List"))
o:depends("filter_keyword_mode", "2")
o:depends("filter_keyword_mode", "3")
o:depends("filter_keyword_mode", "4")

if #ss_type > 0 then
	o = s:option(ListValue, "ss_type", translatef("%s Node Use Type", "Shadowsocks"))
	o.default = "global"
	o:value("global", translate("Use global config"))
	for key, value in pairs(ss_type) do
		o:value(value)
	end
end

if #trojan_type > 0 then
	o = s:option(ListValue, "trojan_type", translatef("%s Node Use Type", "Trojan"))
	o.default = "global"
	o:value("global", translate("Use global config"))
	for key, value in pairs(trojan_type) do
		o:value(value)
	end
end

if #vmess_type > 0 then
	o = s:option(ListValue, "vmess_type", translatef("%s Node Use Type", "VMess"))
	o.default = "global"
	o:value("global", translate("Use global config"))
	for key, value in pairs(vmess_type) do
		o:value(value)
	end
end

if #vless_type > 0 then
	o = s:option(ListValue, "vless_type", translatef("%s Node Use Type", "VLESS"))
	o.default = "global"
	o:value("global", translate("Use global config"))
	for key, value in pairs(vless_type) do
		o:value(value)
	end
end

if #hysteria2_type > 0 then
	o = s:option(ListValue, "hysteria2_type", translatef("%s Node Use Type", "Hysteria2"))
	o.default = "global"
	o:value("global", translate("Use global config"))
	for key, value in pairs(hysteria2_type) do
		o:value(value)
	end
end

o = s:option(ListValue, "domain_strategy", "Sing-box " .. translate("Domain Strategy"), translate("Set the default domain resolution strategy for the sing-box node."))
o.default = "global"
o:value("global", translate("Use global config"))
o:value("", translate("Auto"))
o:value("prefer_ipv4", translate("Prefer IPv4"))
o:value("prefer_ipv6", translate("Prefer IPv6"))
o:value("ipv4_only", translate("IPv4 Only"))
o:value("ipv6_only", translate("IPv6 Only"))

---- Enable auto update subscribe
o = s:option(Flag, "auto_update", translate("Enable auto update subscribe"))
o.default = 0
o.rmempty = false

---- Week Update
o = s:option(ListValue, "week_update", translate("Update Mode"))
o:value(8, translate("Loop Mode"))
o:value(7, translate("Every day"))
o:value(1, translate("Every Monday"))
o:value(2, translate("Every Tuesday"))
o:value(3, translate("Every Wednesday"))
o:value(4, translate("Every Thursday"))
o:value(5, translate("Every Friday"))
o:value(6, translate("Every Saturday"))
o:value(0, translate("Every Sunday"))
o.default = 7
o:depends("auto_update", true)
o.rmempty = true

---- Time Update
o = s:option(ListValue, "time_update", translate("Update Time(every day)"))
for t = 0, 23 do o:value(t, t .. ":00") end
o.default = 0
o:depends("week_update", "0")
o:depends("week_update", "1")
o:depends("week_update", "2")
o:depends("week_update", "3")
o:depends("week_update", "4")
o:depends("week_update", "5")
o:depends("week_update", "6")
o:depends("week_update", "7")
o.rmempty = true

---- Interval Update
o = s:option(ListValue, "interval_update", translate("Update Interval(hour)"))
for t = 1, 24 do o:value(t, t .. " " .. translate("hour")) end
o.default = 2
o:depends("week_update", "8")
o.rmempty = true

o = s:option(ListValue, "access_mode", translate("Subscribe URL Access Method"))
o.default = ""
o:value("", translate("Auto"))
o:value("direct", translate("Direct Connection"))
o:value("proxy", translate("Proxy"))

o = s:option(Value, "user_agent", translate("User-Agent"))
o.default = "passwall"
o:value("passwall", "PassWall")
o:value("v2rayN/9.99", "v2rayN")
o:value("curl", "Curl")
o:value("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0", "Edge for Linux")
o:value("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0", "Edge for Windows")

o = s:option(ListValue, "chain_proxy", translate("Chain Proxy"))
o:value("", translate("Close(Not use)"))
o:value("1", translate("Preproxy Node"))
o:value("2", translate("Landing Node"))

local descrStr = "Chained proxy works only with Xray or Sing-box nodes.<br>"
descrStr = descrStr .. "The chained node must be the same type as your subscription node (Xray with Xray, Sing-box with Sing-box).<br>"
descrStr = descrStr .. "You can only use manual or imported nodes as chained nodes."
descrStr = translate(descrStr) .. "<br>" .. translate("Only support a layer of proxy.")

o = s:option(ListValue, "preproxy_node", translate("Preproxy Node"))
o:depends({ ["chain_proxy"] = "1" })
o.description = descrStr

o = s:option(ListValue, "to_node", translate("Landing Node"))
o:depends({ ["chain_proxy"] = "2" })
o.description = descrStr

for k, v in pairs(nodes_table) do
	if (v.type == "Xray" or v.type == "sing-box") and (not v.chain_proxy or v.chain_proxy == "") and v.add_mode ~= "2" then
		s.fields["preproxy_node"]:value(v.id, v.remark)
		s.fields["to_node"]:value(v.id, v.remark)
	end
end

return m
