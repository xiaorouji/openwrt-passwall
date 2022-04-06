local api = require "luci.model.cbi.passwall2.api.api"
local appname = api.appname
local sys = api.sys
local has_chnlist = api.fs.access("/usr/share/passwall2/rules/chnlist")

m = Map(appname)

-- [[ ACLs Settings ]]--
s = m:section(TypedSection, "acl_rule", translate("ACLs"), "<font color='red'>" .. translate("ACLs is a tools which used to designate specific IP proxy mode.") .. "</font>")
s.template = "cbi/tblsection"
s.sortable = true
s.anonymous = true
s.addremove = true
s.extedit = api.url("acl_config", "%s")
function s.create(e, t)
    t = TypedSection.create(e, t)
    luci.http.redirect(e.extedit:format(t))
end

---- Enable
o = s:option(Flag, "enabled", translate("Enable"))
o.default = 1
o.rmempty = false

---- Remarks
o = s:option(Value, "remarks", translate("Remarks"))
o.rmempty = true

local mac_t = {}
sys.net.mac_hints(function(e, t)
    mac_t[e] = {
        ip = t,
        mac = e
    }
end)

o = s:option(DummyValue, "sources", translate("Source"))
o.rawhtml = true
o.cfgvalue = function(t, n)
    local e = ''
    local v = Value.cfgvalue(t, n) or ''
    string.gsub(v, '[^' .. " " .. ']+', function(w)
        local a = w
        if mac_t[w] then
            a = a .. ' (' .. mac_t[w].ip .. ')'
        end
        if #e > 0 then
            e = e .. "<br />"
        end
        e = e .. a
    end)
    return e
end

return m
