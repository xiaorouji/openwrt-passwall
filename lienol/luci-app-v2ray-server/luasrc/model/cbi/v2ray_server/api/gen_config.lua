local ucursor = require"luci.model.uci".cursor()
local json = require "luci.jsonc"
local server_section = arg[1]
local server = ucursor:get_all("v2ray_server", server_section)

local settings = nil
local routing = nil
local outbounds = {
    {protocol = "freedom"},
    {protocol = "blackhole", tag = "blocked"}
}

if server.protocol == "vmess" then
    if server.VMess_id then
        local clients = {}
        for i = 1, #server.VMess_id do
            clients[i] = {
                id = server.VMess_id[i],
                level = tonumber(server.VMess_level),
                alterId = tonumber(server.VMess_alterId)
            }
        end
        settings = {clients = clients}
    end
elseif server.protocol == "socks" then
    settings = {
        auth = (server.socks_username == nil and server.socks_password == nil) and
            "noauth" or "password",
        accounts = {
            {
                user = (server.socks_username == nil) and "" or
                    server.socks_username,
                pass = (server.socks_password == nil) and "" or
                    server.socks_password
            }
        }
    }
elseif server.protocol == "http" then
    settings = {
        allowTransparent = false,
        accounts = {
            {
                user = (server.http_username == nil) and "" or
                    server.http_username,
                pass = (server.http_password == nil) and "" or
                    server.http_password
            }
        }
    }
elseif server.protocol == "shadowsocks" then
    settings = {
        method = server.ss_method,
        password = server.ss_password,
        level = tonumber(server.ss_level),
        network = server.ss_network,
        ota = (server.ss_ota == '1') and true or false
    }
end

if server.accept_lan == nil or server.accept_lan == "0" then
    routing = {
        domainStrategy = "IPOnDemand",
        rules = {
            {
                type = "field",
                ip = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
                outboundTag = "blocked"
            }
        }
    }
end

if server.transit_node and server.transit_node ~= "nil" then
    local node = ucursor:get_all("passwall", server.transit_node)
    if node and node ~= "nil" and node.type and node.type == "V2ray" then
        local transit_node = {
            tag = "transit",
            protocol = node.v2ray_protocol or "vmess",
            mux = {
                enabled = (node.v2ray_mux == "1") and true or false,
                concurrency = (node.v2ray_mux_concurrency) and tonumber(node.v2ray_mux_concurrency) or 8
            },
            -- 底层传输配置
            streamSettings = (node.v2ray_protocol == "vmess") and {
                network = node.v2ray_transport,
                security = node.v2ray_stream_security,
                tlsSettings = (node.v2ray_stream_security == "tls") and {
                    serverName = node.tls_serverName,
                    allowInsecure = (node.tls_allowInsecure == "1") and true or false
                } or nil,
                tcpSettings = (node.v2ray_transport == "tcp") and {
                    header = {
                        type = node.v2ray_tcp_guise,
                        request = {
                            path = node.v2ray_tcp_guise_http_path or {"/"},
                            headers = {
                                Host = node.v2ray_tcp_guise_http_host or {}
                            }
                        } or {}
                    }
                } or nil,
                kcpSettings = (node.v2ray_transport == "mkcp") and {
                    mtu = tonumber(node.v2ray_mkcp_mtu),
                    tti = tonumber(node.v2ray_mkcp_tti),
                    uplinkCapacity = tonumber(node.v2ray_mkcp_uplinkCapacity),
                    downlinkCapacity = tonumber(node.v2ray_mkcp_downlinkCapacity),
                    congestion = (node.v2ray_mkcp_congestion == "1") and true or false,
                    readBufferSize = tonumber(node.v2ray_mkcp_readBufferSize),
                    writeBufferSize = tonumber(node.v2ray_mkcp_writeBufferSize),
                    header = {type = node.v2ray_mkcp_guise}
                } or nil,
                wsSettings = (node.v2ray_transport == "ws") and {
                    path = node.v2ray_ws_path or "",
                    headers = (node.v2ray_ws_host ~= nil) and {Host = node.v2ray_ws_host} or nil
                } or nil,
                httpSettings = (node.v2ray_transport == "h2") and {
                    path = node.v2ray_h2_path, host = node.v2ray_h2_host
                } or nil,
                dsSettings = (node.v2ray_transport == "ds") and {
                    path = node.v2ray_ds_path
                } or nil,
                quicSettings = (node.v2ray_transport == "quic") and {
                    security = node.v2ray_quic_security,
                    key = node.v2ray_quic_key,
                    header = {type = node.v2ray_quic_guise}
                } or nil
            } or nil,
            settings = {
                vnext = (node.v2ray_protocol == "vmess") and {
                    {
                        address = node.address,
                        port = tonumber(node.port),
                        users = {
                            {
                                id = node.v2ray_VMess_id,
                                alterId = tonumber(node.v2ray_VMess_alterId),
                                level = tonumber(node.v2ray_VMess_level),
                                security = node.v2ray_security
                            }
                        }
                    }
                } or nil,
                servers = (node.v2ray_protocol == "http" or node.v2ray_protocol == "socks" or node.v2ray_protocol == "shadowsocks") and {
                    {
                        address = node.address,
                        port = tonumber(node.port),
                        method = node.v2ray_ss_encrypt_method,
                        password = node.password or "",
                        ota = (node.v2ray_ss_ota == '1') and true or false,
                        users = (node.username and node.password) and {
                            {
                                user = node.username or "",
                                pass = node.password or ""
                            }
                        } or nil
                    }
                } or nil
            }
        }
        table.insert(outbounds, 1, transit_node)
    end
end

local v2ray = {
    log = {
        -- error = "/var/log/v2ray.log",
        loglevel = "warning"
    },
    -- 传入连接
    inbounds = {{
        listen = (server.bind_local == "1") and "127.0.0.1" or nil,
        port = tonumber(server.port),
        protocol = server.protocol,
        -- 底层传输配置
        settings = settings,
        streamSettings = (server.protocol == "vmess") and {
            network = server.transport,
            security = (server.tls_enable == '1') and "tls" or "none",
            tlsSettings = (server.tls_enable == '1') and {
                -- serverName = (server.tls_serverName),
                allowInsecure = false,
                disableSystemRoot = false,
                certificates = {
                    {
                        certificateFile = server.tls_certificateFile,
                        keyFile = server.tls_keyFile
                    }
                }
            } or nil,
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
        } or nil
    }},
    -- 传出连接
    outbounds = outbounds,
    routing = routing
}
print(json.stringify(v2ray, 1))
