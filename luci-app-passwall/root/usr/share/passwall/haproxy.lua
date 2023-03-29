#!/usr/bin/lua

local api = require ("luci.passwall.api")
local appname = api.appname
local fs = api.fs
local jsonc = api.jsonc
local uci = api.uci
local sys = api.sys

local log = function(...)
    api.log(...)
end

function get_ip_port_from(str)
    local result_port = sys.exec("echo -n " .. str .. " | sed -n 's/^.*[:#]\\([0-9]*\\)$/\\1/p'")
    local result_ip = sys.exec(string.format("__host=%s;__varport=%s;", str, result_port) .. "echo -n ${__host%%${__varport:+[:#]${__varport}*}}")
    return result_ip, result_port
end

local var = api.get_args(arg)
local haproxy_path = var["-path"]
local haproxy_conf = var["-conf"]

log("HAPROXY 负载均衡...")
fs.mkdir(haproxy_path)
local haproxy_file = haproxy_path .. "/" .. haproxy_conf

local f_out = io.open(haproxy_file, "a")

local haproxy_config = [[
global
    log         127.0.0.1 local2
    chroot      %s
    maxconn     60000
    stats socket  %s/haproxy.sock
    daemon

defaults
    mode                    tcp
    log                     global
    option                  tcplog
    option                  dontlognull
    option http-server-close
    #option forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 2
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 3000
    
resolvers mydns
    nameserver dns1 127.0.0.1:53
    resolve_retries       3
    timeout retry         3s
    hold valid           10s

]]

f_out:write(string.format(haproxy_config, haproxy_path, haproxy_path))

local listens = {}

uci:foreach(appname, "haproxy_config", function(t)
    if t.enabled == "1" then
        local server_address
        local server_port
        local lbss = t.lbss
        local listen_port = tonumber(t.haproxy_port) or 0
        local server_node = uci:get_all(appname, lbss)
        if server_node and server_node.address and server_node.port then
            server_address = server_node.address
            server_port = server_node.port
        else
            server_address, server_port = get_ip_port_from(lbss)
        end
        if server_address and server_port and listen_port > 0 then
            if not listens[listen_port] then
                listens[listen_port] = {}
            end
            t.server_address = server_address
            t.server_port = server_port
            table.insert(listens[listen_port], t)
        else
            log("  - 丢弃1个明显无效的节点")
        end
    end
end)

local sortTable = {}
for i in pairs(listens) do
    if i ~= nil then
        table.insert(sortTable, i)
    end
end
table.sort(sortTable, function(a,b) return (a < b) end)

for i, port in pairs(sortTable) do
    log("  + 入口 0.0.0.0:%s..." % port)

    f_out:write(string.format([[
listen %s
    bind 0.0.0.0:%s
    mode tcp
    balance roundrobin
]], port, port))

    for i, o in ipairs(listens[port]) do
        local server = o.server_address .. ":" .. o.server_port
        local remark = server:gsub("%[", ""):gsub("%]", "")
        f_out:write(string.format([[
    server %s %s weight %s check resolvers mydns inter 1500 rise 1 fall 3 %s
]], remark, server, o.lbweight, o.backup == "1" and "backup" or ""))

        if o.export ~= "0" then
            sys.call(string.format("/usr/share/passwall/app.sh add_ip2route %s %s", o.server_address, o.export))
        end

        log(string.format("  | - 出口节点：%s:%s，权重：%s", o.server_address, o.server_port, o.lbweight))
    end
end

--控制台配置
local console_port = uci:get(appname, "@global_haproxy[0]", "console_port")
local console_user = uci:get(appname, "@global_haproxy[0]", "console_user")
local console_password = uci:get(appname, "@global_haproxy[0]", "console_password")
local str = [[
listen console
    bind 0.0.0.0:%s
    mode http
    stats refresh 30s
    stats uri /
    stats admin if TRUE
    %s
]]
f_out:write(string.format(str, console_port, (console_user and console_user ~= "" and console_password and console_password ~= "") and "stats auth " .. console_user .. ":" .. console_password or ""))
log(string.format("  * 控制台端口：%s", console_port))

f_out:close()
