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
e = t:option(Value, "caddy_file", translate("Caddy path"), translate(
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
e.width = "15%"
e.cfgvalue = function(t, n)
    local str = "未知"
    local protocol = a.uci:get(appname, n, "protocol") or ""
    if protocol == "vmess" then
        str = "Vmess"
    elseif protocol == "shadowsocks" then
        str = "Shadowsocks"
    end
    return str
end

e = t:option(DummyValue, "transport", translate("Transport"))
e.width = "10%"
e.cfgvalue = function(t, n)
    local transport_var = ""
    local str = "未知"
    local protocol = a.uci:get(appname, n, "protocol") or ""
    if protocol == "vmess" then
        transport_var = "transport"
    elseif protocol == "shadowsocks" then
        transport_var = "ss_network"
    end
    local transport = a.uci:get(appname, n, transport_var) or ""
    if transport == "tcp" then
        str = "TCP"
    elseif transport == "udp" then
        str = "UDP"
    elseif transport == "tcp,udp" then
        str = "TCP,UDP"
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

e = t:option(DummyValue, "password", translate("Password"))
e.width = "30%"
e.cfgvalue = function(t, n)
    local password_var = ""
    local protocol = a.uci:get(appname, n, "protocol") or ""
    if protocol == "vmess" then
        password_var = "VMess_id"
    elseif protocol == "shadowsocks" then
        password_var = "ss_password"
    end
    local password = a.uci:get(appname, n, password_var) or ""
    local str = ""
    if type(password) == "table" then
        for i = 1, #password do str = str .. password[i] end
    else
        str = password
    end
    return str
end

a:append(Template("v2ray_server/users_list_status"))

return a
