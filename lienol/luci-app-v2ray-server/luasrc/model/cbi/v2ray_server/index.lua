local o = require "luci.dispatcher"
local fs = require "nixio.fs"
local sys = require "luci.sys"
local cursor = luci.model.uci.cursor()
local appname = "v2ray_server"
local a, t, e

a = Map(appname, translate("V2ray Server"))

t = a:section(TypedSection, "global", translate("Global Settings"))
t.anonymous = true
t.addremove = false

e = t:option(Flag, "enable", translate("Enable"))
e.rmempty = false

t:append(Template("v2ray_server/v2ray"))
t:append(Template("v2ray_server/nginx"))
t:append(Template("v2ray_server/caddy"))

---- Caddy path
e = t:option(Value, "caddy_file", translate("Caddy path"),
             translate(
                 "if you want to run from memory, change the path, such as /tmp/caddy, Then save the application and update it manually."))
e.default = "/usr/bin/caddy"
e.rmempty = false

t = a:section(TypedSection, "user", translate("Users Manager"))
t.anonymous = true
t.addremove = true
t.template = "cbi/tblsection"
t.extedit = o.build_url("admin", "vpn", appname, "config", "%s")
function t.create(e, t)
    local e = TypedSection.create(e, t)
    luci.http.redirect(o.build_url("admin", "vpn", appname, "config", e))
end

function t.remove(t, a)
    t.map.proceed = true
    t.map:del(a)
    luci.http.redirect(o.build_url("admin", "vpn", appname))
end

e = t:option(Flag, "enable", translate("Enable"))
e.width = "5%"
e.rmempty = false

e = t:option(DummyValue, "status", translate("Status"))
e.template = "v2ray_server/users_status"
e.value = translate("Collecting data...")

e = t:option(DummyValue, "remarks", translate("Remarks"))
e.width = "15%"

e = t:option(DummyValue, "port", translate("Port"))
e.width = "10%"

e = t:option(DummyValue, "protocol", translate("Protocol"))
e.width = "10%"
e.cfgvalue = function(t, n)
    local str = "未知"
    local transport = a.uci:get(appname, n, "protocol") or ""
    if transport == "vmess" then
        str = "Vmess"
    -- To Do
    end
    return str
end

e = t:option(DummyValue, "transport", translate("Transport"))
e.width = "10%"
e.cfgvalue = function(t, n)
    local str = "未知"
    local transport = a.uci:get(appname, n, "transport") or ""
    if transport == "tcp" then
        str = "TCP"
    elseif transport == "mkcp" then
        str = "mKCP"
    elseif transport == "ws" then
        str = "WebSocket"
    elseif transport == "h2" then
        str = "HTTP/2"
    elseif transport == "quic" then
        str = "QUIC"
    end
    return str
end

e = t:option(DummyValue, "VMess_id", translate("ID"))
e.width = "30%"

a:append(Template("v2ray_server/users_list_status"))

return a
