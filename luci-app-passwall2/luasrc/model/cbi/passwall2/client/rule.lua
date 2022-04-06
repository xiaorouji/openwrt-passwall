local api = require "luci.model.cbi.passwall2.api.api"
local appname = api.appname

m = Map(appname)
-- [[ Rule Settings ]]--
s = m:section(TypedSection, "global_rules", translate("Rule status"))
s.anonymous = true

s:append(Template(appname .. "/rule/rule_version"))

---- Auto Update
o = s:option(Flag, "auto_update", translate("Enable auto update rules"))
o.default = 0
o.rmempty = false

---- Week Update
o = s:option(ListValue, "week_update", translate("Week update rules"))
o:value(7, translate("Every day"))
for e = 1, 6 do o:value(e, translate("Week") .. e) end
o:value(0, translate("Week") .. translate("day"))
o.default = 0
o:depends("auto_update", true)

---- Time Update
o = s:option(ListValue, "time_update", translate("Day update rules"))
for e = 0, 23 do o:value(e, e .. translate("oclock")) end
o.default = 0
o:depends("auto_update", true)

o = s:option(Value, "v2ray_location_asset", translate("Location of V2ray/Xray asset"), translate("This variable specifies a directory where geoip.dat and geosite.dat files are."))
o.default = "/usr/share/v2ray/"
o.rmempty = false

s = m:section(TypedSection, "shunt_rules", "V2ray/Xray " .. translate("Shunt Rule"), "<a style='color: red'>" .. translate("Please note attention to the priority, the higher the order, the higher the priority.") .. "</a>")
s.template = "cbi/tblsection"
s.anonymous = false
s.addremove = true
s.sortable = true
s.extedit = api.url("shunt_rules", "%s")
function s.create(e, t)
    TypedSection.create(e, t)
    luci.http.redirect(e.extedit:format(t))
end
function s.remove(e, t)
    m.uci:foreach(appname, "nodes", function(s)
        if s["protocol"] and s["protocol"] == "_shunt" then
            m:del(s[".name"], t)
        end
    end)
    TypedSection.remove(e, t)
end

o = s:option(DummyValue, "remarks", translate("Remarks"))

return m
