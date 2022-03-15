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
local run_type = var["-run_type"]
local local_addr = var["-local_addr"]
local local_port = var["-local_port"]
local server_host = var["-server_host"] or node.address
local server_port = var["-server_port"] or node.port

if api.is_ipv6(server_host) then
    server_host = api.get_ipv6_full(server_host)
end
local server = server_host .. ":" .. server_port

local config = {
    listen = run_type .. "://" .. local_addr .. ":" .. local_port,
    proxy = node.protocol .. "://" .. node.username .. ":" .. node.password .. "@" .. server
}

print(jsonc.stringify(config, 1))
