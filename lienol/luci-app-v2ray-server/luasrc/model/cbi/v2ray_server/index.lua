local i = require "luci.dispatcher"
local e = require "nixio.fs"
local e = require "luci.sys"
local e = luci.model.uci.cursor()
local o = "v2ray_server"
local a, t, e
a = Map(o, translate("V2ray Server"))

t = a:section(TypedSection, "global", translate("Global Settings"))
t.anonymous = true
t.addremove = false
e = t:option(Flag, "enable", translate("Enable"))
e.rmempty = false
t:append(Template("v2ray_server/v2ray"))
t:append(Template("v2ray_server/nginx"))
t:append(Template("v2ray_server/caddy"))
e = t:option(Value, "caddy_file", translate("Caddy path"), translate(
                 "if you want to run from memory, change the path, such as /tmp/caddy, Then save the application and update it manually."))
e.default = "/usr/bin/caddy"
e.rmempty = false

t = a:section(TypedSection, "user", translate("Users Manager"))
t.anonymous = true
t.addremove = true
t.template = "cbi/tblsection"
t.extedit = i.build_url("admin", "vpn", o, "config", "%s")
function t.create(t, e)
    local e = TypedSection.create(t, e)
    luci.http.redirect(i.build_url("admin", "vpn", o, "config", e))
end
function t.remove(t, a)
    t.map.proceed = true
    t.map:del(a)
    luci.http.redirect(i.build_url("admin", "vpn", o))
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
e.cfgvalue = function(t, i)
    local t = "未知"
    local a = a.uci:get(o, i, "protocol") or ""
    if a == "vmess" then
        t = "Vmess"
    elseif a == "shadowsocks" then
        t = "Shadowsocks"
    end
    return t
end
e = t:option(DummyValue, "transport", translate("Transport"))
e.width = "10%"
e.cfgvalue = function(t, s)
    local i = ""
    local t = "未知"
    local n = a.uci:get(o, s, "protocol") or ""
    if n == "vmess" then
        i = "transport"
    elseif n == "shadowsocks" then
        i = "ss_network"
    end
    local a = a.uci:get(o, s, i) or ""
    if a == "tcp" then
        t = "TCP"
    elseif a == "udp" then
        t = "UDP"
    elseif a == "tcp,udp" then
        t = "TCP,UDP"
    elseif a == "mkcp" then
        t = "mKCP"
    elseif a == "ws" then
        t = "WebSocket"
    elseif a == "h2" then
        t = "HTTP/2"
    elseif a == "quic" then
        t = "QUIC"
    end
    return t
end
e = t:option(DummyValue, "password", translate("Password"))
e.width = "30%"
e.cfgvalue = function(e, t)
    local e = ""
    local i = a.uci:get(o, t, "protocol") or ""
    if i == "vmess" then
        e = "VMess_id"
    elseif i == "shadowsocks" then
        e = "ss_password"
    end
    local e = a.uci:get(o, t, e) or ""
    local t = ""
    if type(e) == "table" then
        for a = 1, #e do t = t .. e[a] end
    else
        t = e
    end
    return t
end

a:append(Template("v2ray_server/log"))

a:append(Template("v2ray_server/users_list_status"))
return a
