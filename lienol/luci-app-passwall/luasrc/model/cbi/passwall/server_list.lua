local d = require "luci.dispatcher"
local fs = require "nixio.fs"
local sys = require "luci.sys"
local uci = require"luci.model.uci".cursor()
local appname = "passwall"

m = Map(appname)

-- [[ Other Settings ]]--
s = m:section(TypedSection, "global_other")
s.anonymous = true

---- Auto Ping
o = s:option(Flag, "auto_ping", translate("Auto Ping"),
             translate("This will automatically ping the server for latency"))
o.default = 0

-- [[ Add the server via the link ]]--
s:append(Template("passwall/server_list/link_add_server"))

-- [[ Servers List ]]--
s = m:section(TypedSection, "servers")
s.anonymous = true
s.sortable = true
s.addremove = true
s.template = "cbi/tblsection"
s.extedit = d.build_url("admin", "vpn", "passwall", "serverconfig", "%s")
function s.create(e, t)
    local e = TypedSection.create(e, t)
    luci.http.redirect(
        d.build_url("admin", "vpn", "passwall", "serverconfig", e))
end

function s.remove(t, a)
    s.map.proceed = true
    s.map:del(a)
    luci.http.redirect(d.build_url("admin", "vpn", "passwall", "server_list"))
end

---- Node Remarks
o = s:option(DummyValue, "remarks", translate("Node Remarks"))

---- Add Mode
o = s:option(DummyValue, "add_mode", translate("Add Mode"))
o.cfgvalue = function(t, n)
    local v = Value.cfgvalue(t, n)
    if v and v ~= '' then
        return v
    else
        return '手动'
    end
    return str
end

---- Server Type
o = s:option(DummyValue, "server_type", translate("Server Type"))

---- Server Address
o = s:option(DummyValue, "server", translate("Server Address"))

---- Server Port
o = s:option(DummyValue, "server_port", translate("Server Port"))

---- Encrypt Method
--[[o = s:option(DummyValue, "encrypt_method", translate("Encrypt Method"))
o.width="15%"
o.cfgvalue=function(t, n)
local str="无"
local type = m.uci:get(appname, n, "server_type") or ""
if type == "SSR" then
	return m.uci:get(appname, n, "ssr_encrypt_method")
elseif type == "SS" then
	return m.uci:get(appname, n, "ss_encrypt_method")
elseif type == "V2ray" then
	return m.uci:get(appname, n, "v2ray_security")
end
return str
end--]]

---- Ping
o = s:option(DummyValue, "server", translate("Ping"))
if uci:get(appname, "@global_other[0]", "auto_ping") == "0" then
    o.template = "passwall/server_list/ping"
else
    o.template = "passwall/server_list/auto_ping"
end

---- Apply
o = s:option(DummyValue, "apply", translate("Apply"))
o.template = "passwall/server_list/apply"

m:append(Template("passwall/server_list/server_list"))

if luci.http.formvalue("cbi.apply") then
    luci.http.redirect(d.build_url("admin", "vpn", "passwall", "server_list"))
end

return m
