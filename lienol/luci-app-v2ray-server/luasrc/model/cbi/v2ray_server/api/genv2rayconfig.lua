local ucursor = require"luci.model.uci".cursor()
local json = require "luci.jsonc"
local server_section = arg[1]
local server = ucursor:get_all("v2ray_server", server_section)

local clients = {}

if server.protocol == "vmess" and server.VMess_id then
    for i = 1, #server.VMess_id do
        clients[i] = {
            id = server.VMess_id[i],
            level = tonumber(server.VMess_level),
            alterId = tonumber(server.VMess_alterId)
        }
    end
end

local v2ray = {
    log = {
        -- error = "/var/log/v2ray.log",
        loglevel = "warning"
    },
    -- 传入连接
    inbound = {
        listen = (server.bind_local) and "127.0.0.1" or nil,
        port = tonumber(server.port),
        protocol = server.protocol,
        -- 底层传输配置
        settings = (server.protocol == "vmess") and {clients = clients} or
            (server.protocol == "shadowsocks") and {
            method = server.ss_method,
            password = server.ss_password,
            level = tonumber(server.ss_level),
            network = server.ss_network,
            ota = (server.ss_ota == '1') and true or false
        } or nil,
        streamSettings = (server.protocol == "vmess") and {
            network = server.transport,
            security = (server.tls == '1' or server.transport == "h2") and "tls" or
                "none",
            kcpSettings = (server.transport == "mkcp") and {
                mtu = tonumber(server.mkcp_mtu),
                tti = tonumber(server.mkcp_tti),
                uplinkCapacity = tonumber(server.mkcp_uplinkCapacity),
                downlinkCapacity = tonumber(server.mkcp_downlinkCapacity),
                congestion = (server.mkcp_congestion == "1") and true or false,
                readBufferSize = tonumber(server.mkcp_readBufferSize),
                writeBufferSize = tonumber(server.mkcp_writeBufferSize),
                header = {type = server.mkcp_guise}
            } or nil,
            wsSettings = (server.transport == "ws") and {
                headers = (server.ws_host) and {Host = server.ws_host} or nil,
                path = server.ws_path
            } or nil,
            httpSettings = (server.transport == "h2") and
                {path = server.h2_path, host = server.h2_host} or nil,
            quicSettings = (server.transport == "quic") and {
                security = server.quic_security,
                key = server.quic_key,
                header = {type = server.quic_guise}
            } or nil
        } or nil,
        tlsSettings = (server.reverse_proxy_enable == '1' and server.transport ==
            "h2") and {
            serverName = (server.reverse_proxy_serverName),
            certificates = {
                {
                    certificateFile = server.reverse_proxy_https_certificateFile,
                    keyFile = server.reverse_proxy_https_keyFile
                }
            }
        } or nil
    },
    -- 传出连接
    outbound = {protocol = "freedom"},
    -- 额外传出连接
    outboundDetour = {{protocol = "blackhole", tag = "blocked"}}
}
print(json.stringify(v2ray, 1))
