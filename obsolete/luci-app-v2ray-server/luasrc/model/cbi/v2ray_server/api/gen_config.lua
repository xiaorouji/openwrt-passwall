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
    if server.vmess_id then
        local clients = {}
        for i = 1, #server.vmess_id do
            clients[i] = {
                id = server.vmess_id[i],
                level = tonumber(server.vmess_level),
                alterId = tonumber(server.alter_id)
            }
        end
        settings = {clients = clients}
    end
elseif server.protocol == "socks" then
    settings = {
        auth = (server.username == nil and server.password == nil) and "noauth" or "password",
        accounts = {
            {
                user = (server.username == nil) and "" or server.username,
                pass = (server.password == nil) and "" or server.password
            }
        }
    }
elseif server.protocol == "http" then
    settings = {
        allowTransparent = false,
        accounts = {
            {
                user = (server.username == nil) and "" or server.username,
                pass = (server.password == nil) and "" or server.password
            }
        }
    }
elseif server.protocol == "shadowsocks" then
    settings = {
        method = server.ss_method,
        password = server.password,
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
            protocol = node.protocol or "vmess",
            mux = {
                enabled = (node.mux == "1") and true or false,
                concurrency = (node.mux_concurrency) and tonumber(node.mux_concurrency) or 8
            },
            -- 底层传输配置
            streamSettings = (node.protocol == "vmess") and {
                network = node.transport,
                security = node.stream_security,
                tlsSettings = (node.stream_security == "tls") and {
                    serverName = node.tls_serverName,
                    allowInsecure = (node.tls_allowInsecure == "1") and true or false
                } or nil,
                tcpSettings = (node.transport == "tcp") and {
                    header = {
                        type = node.tcp_guise,
                        request = {
                            path = node.tcp_guise_http_path or {"/"},
                            headers = {
                                Host = node.tcp_guise_http_host or {}
                            }
                        } or {}
                    }
                } or nil,
                kcpSettings = (node.transport == "mkcp") and {
                    mtu = tonumber(node.mkcp_mtu),
                    tti = tonumber(node.mkcp_tti),
                    uplinkCapacity = tonumber(node.mkcp_uplinkCapacity),
                    downlinkCapacity = tonumber(node.mkcp_downlinkCapacity),
                    congestion = (node.mkcp_congestion == "1") and true or false,
                    readBufferSize = tonumber(node.mkcp_readBufferSize),
                    writeBufferSize = tonumber(node.mkcp_writeBufferSize),
                    header = {type = node.mkcp_guise}
                } or nil,
                wsSettings = (node.transport == "ws") and {
                    path = node.ws_path or "",
                    headers = (node.ws_host ~= nil) and {Host = node.ws_host} or nil
                } or nil,
                httpSettings = (node.transport == "h2") and {
                    path = node.h2_path, host = node.h2_host
                } or nil,
                dsSettings = (node.transport == "ds") and {
                    path = node.ds_path
                } or nil,
                quicSettings = (node.transport == "quic") and {
                    security = node.quic_security,
                    key = node.quic_key,
                    header = {type = node.quic_guise}
                } or nil
            } or nil,
            settings = {
                vnext = (node.protocol == "vmess") and {
                    {
                        address = node.address,
                        port = tonumber(node.port),
                        users = {
                            {
                                id = node.vmess_id,
                                alterId = tonumber(node.alter_id),
                                level = tonumber(node.vmess_level),
                                security = node.security
                            }
                        }
                    }
                } or nil,
                servers = (node.protocol == "http" or node.protocol == "socks" or node.protocol == "shadowsocks") and {
                    {
                        address = node.address,
                        port = tonumber(node.port),
                        method = node.ss_encrypt_method,
                        password = node.password or "",
                        ota = (node.ss_ota == '1') and true or false,
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
        --error = string.format("/var/log/v2ray_%s.log", server[".name"]),
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
            tcpSettings = (server.transport == "tcp") and {
                header = {
                    type = server.tcp_guise,
                    request = {
                        path = server.tcp_guise_http_path or {"/"},
                        headers = {
                            Host = server.tcp_guise_http_host or {}
                        }
                    } or {}
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
