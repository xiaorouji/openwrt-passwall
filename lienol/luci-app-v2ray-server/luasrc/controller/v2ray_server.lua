-- Copyright 2018-2019 Lienol <lawlienol@gmail.com>
module("luci.controller.v2ray_server", package.seeall)
local e = require "luci.http"
local i = require "luci.model.cbi.v2ray_server.api.v2ray"
local o = require "luci.model.cbi.v2ray_server.api.caddy"
function index()
    if not nixio.fs.access("/etc/config/v2ray_server") then return end
    entry({"admin", "vpn"}, firstchild(), "VPN", 45).dependent = false
    entry({"admin", "vpn", "v2ray_server"}, cbi("v2ray_server/index"),
          _("V2ray Server"), 3).dependent = true
    entry({"admin", "vpn", "v2ray_server", "config"}, cbi("v2ray_server/config")).leaf =
        true
    entry({"admin", "vpn", "v2ray_server", "users_status"},
          call("v2ray_users_status")).leaf = true
    entry({"admin", "vpn", "v2ray_server", "check"}, call("v2ray_check")).leaf =
        true
    entry({"admin", "vpn", "v2ray_server", "update"}, call("v2ray_update")).leaf =
        true
    entry({"admin", "vpn", "v2ray_server", "caddy_check"}, call("caddy_check")).leaf =
        true
    entry({"admin", "vpn", "v2ray_server", "caddy_update"}, call("caddy_update")).leaf =
        true
    entry({"admin", "vpn", "v2ray_server", "get_log"}, call("get_log")).leaf =
        true
    entry({"admin", "vpn", "v2ray_server", "clear_log"}, call("clear_log")).leaf =
        true
end
local function t(t)
    e.prepare_content("application/json")
    e.write_json(t or {code = 1})
end
function v2ray_users_status()
    local e = {}
    e.index = luci.http.formvalue("index")
    e.status = luci.sys.call(
                   "ps -w| grep -v grep | grep '/var/etc/v2ray_server/" ..
                       luci.http.formvalue("id") .. "' >/dev/null") == 0
    t(e)
end
function v2ray_check()
    local e = i.to_check("")
    t(e)
end
function v2ray_update()
    local a = nil
    local o = e.formvalue("task")
    if o == "extract" then
        a = i.to_extract(e.formvalue("file"), e.formvalue("subfix"))
    elseif o == "move" then
        a = i.to_move(e.formvalue("file"))
    else
        a = i.to_download(e.formvalue("url"))
    end
    t(a)
end
function caddy_check()
    local e = o.to_check("")
    t(e)
end
function caddy_update()
    local a = nil
    local i = e.formvalue("task")
    if i == "extract" then
        a = o.to_extract(e.formvalue("file"), e.formvalue("subfix"))
    elseif i == "move" then
        a = o.to_move(e.formvalue("file"))
    else
        a = o.to_download(e.formvalue("url"))
    end
    t(a)
end

function get_log()
    luci.http.write(luci.sys.exec("cat /var/log/v2ray_server/app.log"))
end

function clear_log() luci.sys.call("rm -rf > /var/log/v2ray_server/app.log") end
