local api = require "luci.model.cbi.passwall.api.api"
local appname = api.appname

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
    nodes_table[#nodes_table + 1] = e
end

m = Map(appname)

-- [[ Auto Switch Settings ]]--
s = m:section(TypedSection, "auto_switch")
s.anonymous = true

---- Enable
o = s:option(Flag, "enable", translate("Enable"))
o.default = 0
o.rmempty = false

o = s:option(Value, "testing_time", translate("How often to test"), translate("Units:minutes"))
o.datatype = "uinteger"
o.default = 1

o = s:option(Value, "connect_timeout", translate("Timeout seconds"), translate("Units:seconds"))
o.datatype = "uinteger"
o.default = 3

o = s:option(Value, "retry_num", translate("Timeout retry num"))
o.datatype = "uinteger"
o.default = 3
    
o = s:option(DynamicList, "tcp_node", "TCP " .. translate("List of backup nodes"))
for k, v in pairs(nodes_table) do
    if v.node_type == "normal" then
        o:value(v.id, v["remark"])
    end
end

o = s:option(Flag, "restore_switch", "TCP " .. translate("Restore Switch"), translate("When detects main node is available, switch back to the main node."))

m:append(Template(appname .. "/auto_switch/footer"))

return m
