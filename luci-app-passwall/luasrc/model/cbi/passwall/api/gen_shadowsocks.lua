local api = require "luci.model.cbi.passwall.api.api"
local uci = api.uci
local jsonc = api.jsonc

local var = api.get_args(arg)
local node_id = var["-node"]
if not node_id then
    print("-node 不能为空")
    return
end
local node = uci:get_all("passwall", node_id)
local local_addr = var["-local_addr"]
local local_port = var["-local_port"]
local server_host = var["-server_host"] or node.address
local server_port = var["-server_port"] or node.port
local protocol = var["-protocol"]
local mode = var["-mode"]

if api.is_ipv6(server_host) then
    server_host = api.get_ipv6_only(server_host)
end
local server = server_host

local config = {
    server = server,
    server_port = tonumber(server_port),
    local_address = local_addr,
    local_port = tonumber(local_port),
    password = node.password,
    method = node.method,
    timeout = tonumber(node.timeout),
    fast_open = (node.tcp_fast_open and node.tcp_fast_open == "true") and true or false,
    reuse_port = true,
    tcp_tproxy = var["-tcp_tproxy"] and true or nil
}

if node.type == "SS" then
    if node.plugin and node.plugin ~= "none" then
        config.plugin = node.plugin
        config.plugin_opts = node.plugin_opts or nil
    end
    config.mode = mode
elseif node.type == "SS-Rust" then
    config = {
        servers = {
            {
                address = server,
                port = tonumber(server_port),
                method = node.method,
                password = node.password,
                timeout = tonumber(node.timeout),
                plugin = (node.plugin and node.plugin ~= "none") and node.plugin or nil,
                plugin_opts = (node.plugin and node.plugin ~= "none") and node.plugin_opts or nil
            }
        },
        locals = {
            {
                protocol = protocol,
                local_address = local_addr,
                local_port = tonumber(local_port),
                mode = mode,
                tcp_redir = var["-tcp_tproxy"] and "tproxy" or nil
            }
        },
        fast_open = (node.tcp_fast_open and node.tcp_fast_open == "true") and true or false
    }
elseif node.type == "SSR" then
    config.protocol = node.protocol
    config.protocol_param = node.protocol_param
    config.obfs = node.obfs
    config.obfs_param = node.obfs_param
end

print(jsonc.stringify(config, 1))
