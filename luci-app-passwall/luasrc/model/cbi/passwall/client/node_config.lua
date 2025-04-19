local api = require "luci.passwall.api"
local appname = "passwall"

m = Map(appname, translate("Node Config"))
m.redirect = api.url("node_list")
api.set_apply_on_parse(m)

if not arg[1] or not m:get(arg[1]) then
	luci.http.redirect(m.redirect)
end

s = m:section(NamedSection, arg[1], "nodes", "")
s.addremove = false
s.dynamic = false

o = s:option(DummyValue, "passwall", " ")
o.rawhtml  = true
o.template = "passwall/node_list/link_share_man"
o.value = arg[1]

o = s:option(Value, "remarks", translate("Node Remarks"))
o.default = translate("Remarks")
o.rmempty = false

o = s:option(ListValue, "type", translate("Type"))

if api.is_finded("ipt2socks") then
	local function _n(name)
		return "socks_" .. name
	end

	s.fields["type"]:value("Socks", translate("Socks"))

	o = s:option(ListValue, _n("del_protocol")) --始终隐藏，用于删除 protocol
	o:depends({ [_n("__hide")] = "1" })
	o.rewrite_option = "protocol"

	o = s:option(Value, _n("address"), translate("Address (Support Domain Name)"))

	o = s:option(Value, _n("port"), translate("Port"))
	o.datatype = "port"

	o = s:option(Value, _n("username"), translate("Username"))
	
	o = s:option(Value, _n("password"), translate("Password"))
	o.password = true

	api.luci_types(arg[1], m, s, "Socks", "socks_")
end

local fs = api.fs
local types_dir = "/usr/lib/lua/luci/model/cbi/passwall/client/type/"

local type_table = {}
for filename in fs.dir(types_dir) do
	table.insert(type_table, filename)
end
table.sort(type_table)

for index, value in ipairs(type_table) do
	local p_func = loadfile(types_dir .. value)
	setfenv(p_func, getfenv(1))(m, s)
end

return m
