module("luci.model.cbi.passwall2.api.gen_v2ray", package.seeall)
local api = require "luci.model.cbi.passwall2.api.api"

local var = api.get_args(arg)
local flag = var["-flag"]
local node_id = var["-node"]
local tcp_proxy_way = var["-tcp_proxy_way"]
local redir_port = var["-redir_port"]
local sniffing = var["-sniffing"]
local route_only = var["-route_only"]
local local_socks_address = var["-local_socks_address"] or "0.0.0.0"
local local_socks_port = var["-local_socks_port"]
local local_socks_username = var["-local_socks_username"]
local local_socks_password = var["-local_socks_password"]
local local_http_address = var["-local_http_address"] or "0.0.0.0"
local local_http_port = var["-local_http_port"]
local local_http_username = var["-local_http_username"]
local local_http_password = var["-local_http_password"]
local dns_listen_port = var["-dns_listen_port"]
local local_dns_ip = var["-local_dns_ip"] or "119.29.29.29"
local local_dns_address = var["-local_dns_address"] or "tcp+local://119.29.29.29"
local local_dns_port = var["-local_dns_port"] or 53
local dns_server = var["-dns_server"]
local dns_direct_domains = {}
local dns_direct_expectIPs = {}
local dns_tcp_server = var["-dns_tcp_server"]
local dns_cache = var["-dns_cache"]
local doh_url = var["-doh_url"]
local doh_host = var["-doh_host"]
local dns_client_ip = var["-dns_client_ip"]
local dns_query_strategy = var["-dns_query_strategy"]
local dns_fakedns = var["-dns_fakedns"]
local loglevel = var["-loglevel"] or "warning"
local new_port

local uci = api.uci
local sys = api.sys
local jsonc = api.jsonc
local appname = api.appname
local fs = api.fs
local dns = nil
local fakedns = nil
local inbounds = {}
local outbounds = {}
local routing = nil

local function get_new_port()
    if new_port then
        new_port = tonumber(sys.exec(string.format("echo -n $(/usr/share/%s/app.sh get_new_port %s tcp)", appname, new_port + 1)))
    else
        new_port = tonumber(sys.exec(string.format("echo -n $(/usr/share/%s/app.sh get_new_port auto tcp)", appname)))
    end
    return new_port
end

local function get_domain_excluded()
    local path = string.format("/usr/share/%s/domains_excluded", appname)
    local content = fs.readfile(path)
    if not content then return nil end
    local hosts = {}
    string.gsub(content, '[^' .. "\n" .. ']+', function(w)
        local s = w:gsub("^%s*(.-)%s*$", "%1") -- Trim
        if s == "" then return end
        if s:find("#") and s:find("#") == 1 then return end
        if not s:find("#") or s:find("#") ~= 1 then table.insert(hosts, s) end
    end)
    if #hosts == 0 then hosts = nil end
    return hosts
end

function gen_outbound(node, tag, proxy_table)
    local proxy = 0
    local proxy_tag = "nil"
    if proxy_table ~= nil and type(proxy_table) == "table" then
        proxy = proxy_table.proxy or 0
        proxy_tag = proxy_table.tag or "nil"
    end
    local result = nil
    if node and node ~= "nil" then
        local node_id = node[".name"]
        if tag == nil then
            tag = node_id
        end

        if node.type == "V2ray" or node.type == "Xray" then
            proxy = 0
            if proxy_tag ~= "nil" then
                node.proxySettings = {
                    tag = proxy_tag,
                    transportLayer = true
                }
            end
        end

        if node.type ~= "V2ray" and node.type ~= "Xray" then
            local relay_port = node.port
            new_port = get_new_port()
            sys.call(string.format('/usr/share/%s/app.sh run_socks "%s"> /dev/null',
                appname,
                string.format("flag=%s node=%s bind=%s socks_port=%s config_file=%s relay_port=%s",
                    new_port, --flag
                    node_id, --node
                    "127.0.0.1", --bind
                    new_port, --socks port
                    string.format("%s_%s_%s_%s.json", flag, tag, node_id, new_port), --config file
                    (proxy == 1 and proxy_tag ~= "nil" and relay_port) and tostring(relay_port) or "" --relay port
                    )
                )
            )
            node = {}
            node.protocol = "socks"
            node.transport = "tcp"
            node.address = "127.0.0.1"
            node.port = new_port
            node.stream_security = "none"
        else
            if node.tls and node.tls == "1" then
                node.stream_security = "tls"
                if node.type == "Xray" and node.xtls and node.xtls == "1" then
                    node.stream_security = "xtls"
                end
            end
        end

        result = {
            _flag_tag = node_id,
            _flag_proxy = proxy,
            _flag_proxy_tag = proxy_tag,
            tag = tag,
            proxySettings = node.proxySettings or nil,
            protocol = node.protocol,
            mux = (node.stream_security ~= "xtls") and {
                enabled = (node.mux == "1") and true or false,
                concurrency = (node.mux_concurrency) and tonumber(node.mux_concurrency) or 8
            } or nil,
            -- 底层传输配置
            streamSettings = (node.protocol == "vmess" or node.protocol == "vless" or node.protocol == "socks" or node.protocol == "shadowsocks" or node.protocol == "trojan") and {
                network = node.transport,
                security = node.stream_security,
                xtlsSettings = (node.stream_security == "xtls") and {
                    serverName = node.tls_serverName,
                    allowInsecure = (node.tls_allowInsecure == "1") and true or false
                } or nil,
                tlsSettings = (node.stream_security == "tls") and {
                    serverName = node.tls_serverName,
                    allowInsecure = (node.tls_allowInsecure == "1") and true or false,
                    fingerprint = (node.type == "Xray" and node.fingerprint and node.fingerprint ~= "disable") and node.fingerprint or nil
                } or nil,
                tcpSettings = (node.transport == "tcp" and node.protocol ~= "socks") and {
                    header = {
                        type = node.tcp_guise or "none",
                        request = (node.tcp_guise == "http") and {
                            path = node.tcp_guise_http_path or {"/"},
                            headers = {
                                Host = node.tcp_guise_http_host or {}
                            }
                        } or nil
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
                    seed = (node.mkcp_seed and node.mkcp_seed ~= "") and node.mkcp_seed or nil,
                    header = {type = node.mkcp_guise}
                } or nil,
                wsSettings = (node.transport == "ws") and {
                    path = node.ws_path or "",
                    headers = (node.ws_host ~= nil) and
                        {Host = node.ws_host} or nil,
                    maxEarlyData = tonumber(node.ws_maxEarlyData) or nil
                } or nil,
                httpSettings = (node.transport == "h2") and {
                    path = node.h2_path,
                    host = node.h2_host,
                    read_idle_timeout = tonumber(node.h2_read_idle_timeout) or nil,
                    health_check_timeout = tonumber(node.h2_health_check_timeout) or nil
                } or nil,
                dsSettings = (node.transport == "ds") and
                    {path = node.ds_path} or nil,
                quicSettings = (node.transport == "quic") and {
                    security = node.quic_security,
                    key = node.quic_key,
                    header = {type = node.quic_guise}
                } or nil,
                grpcSettings = (node.transport == "grpc") and {
                    serviceName = node.grpc_serviceName,
                    multiMode = (node.grpc_mode == "multi") and true or nil,
                    idle_timeout = tonumber(node.grpc_idle_timeout) or nil,
                    health_check_timeout = tonumber(node.grpc_health_check_timeout) or nil,
                    permit_without_stream = (node.grpc_permit_without_stream == "1") and true or nil,
                    initial_windows_size = tonumber(node.grpc_initial_windows_size) or nil
                } or nil
            } or nil,
            settings = {
                vnext = (node.protocol == "vmess" or node.protocol == "vless") and {
                    {
                        address = node.address,
                        port = tonumber(node.port),
                        users = {
                            {
                                id = node.uuid,
                                level = 0,
                                security = (node.protocol == "vmess") and node.security or nil,
                                encryption = node.encryption or "none",
                                flow = node.flow or nil
                            }
                        }
                    }
                } or nil,
                servers = (node.protocol == "socks" or node.protocol == "http" or node.protocol == "shadowsocks" or node.protocol == "trojan") and {
                    {
                        address = node.address,
                        port = tonumber(node.port),
                        method = node.method or nil,
                        flow = node.flow or nil,
                        ivCheck = (node.protocol == "shadowsocks") and node.iv_check == "1" or nil,
                        password = node.password or "",
                        users = (node.username and node.password) and {
                            {
                                user = node.username,
                                pass = node.password
                            }
                        } or nil
                    }
                } or nil
            }
        }
        local alpn = {}
        if node.alpn and node.alpn ~= "default" then
            string.gsub(node.alpn, '[^' .. "," .. ']+', function(w)
                table.insert(alpn, w)
            end)
        end
        if alpn and #alpn > 0 then
            if result.streamSettings.tlsSettings then
                result.streamSettings.tlsSettings.alpn = alpn
            end
            if result.streamSettings.xtlsSettings then
                result.streamSettings.xtlsSettings.alpn = alpn
            end
        end
    end
    return result
end

if true then
    if local_socks_port then
        local inbound = {
            listen = local_socks_address,
            port = tonumber(local_socks_port),
            protocol = "socks",
            settings = {auth = "noauth", udp = true},
            sniffing = {enabled = true, destOverride = {"http", "tls"}}
        }
        if local_socks_username and local_socks_password and local_socks_username ~= "" and local_socks_password ~= "" then
            inbound.settings.auth = "password"
            inbound.settings.accounts = {
                {
                    user = local_socks_username,
                    pass = local_socks_password
                }
            }
        end
        table.insert(inbounds, inbound)
    end
    if local_http_port then
        local inbound = {
            listen = local_http_address,
            port = tonumber(local_http_port),
            protocol = "http",
            settings = {allowTransparent = false}
        }
        if local_http_username and local_http_password and local_http_username ~= "" and local_http_password ~= "" then
            inbound.settings.accounts = {
                {
                    user = local_http_username,
                    pass = local_http_password
                }
            }
        end
        table.insert(inbounds, inbound)
    end

    if redir_port then
        local inbound = {
            port = tonumber(redir_port),
            protocol = "dokodemo-door",
            settings = {network = "tcp,udp", followRedirect = true},
            streamSettings = {sockopt = {tproxy = "tproxy"}},
            sniffing = {enabled = sniffing and true or false, destOverride = {"http", "tls", (dns_fakedns) and "fakedns"}, metadataOnly = false, routeOnly = route_only and true or nil, domainsExcluded = (sniffing and not route_only) and get_domain_excluded() or nil}
        }
        local tcp_inbound = api.clone(inbound)
        tcp_inbound.tag = "tcp_redir"
        tcp_inbound.settings.network = "tcp"
        tcp_inbound.streamSettings.sockopt.tproxy = tcp_proxy_way
        table.insert(inbounds, tcp_inbound)

        local udp_inbound = api.clone(inbound)
        udp_inbound.tag = "udp_redir"
        udp_inbound.settings.network = "udp"
        table.insert(inbounds, udp_inbound)
    end

    local nodes = {}
    if node_id then
        local node = uci:get_all(appname, node_id)
        if node then
            nodes[node_id] = node
        end
    end

    for k, v in pairs(nodes) do
        local node = v
        if node.protocol == "_shunt" then
            local rules = {}

            local default_node_id = node.default_node or "_direct"
            local default_outboundTag
            if default_node_id == "_direct" then
                default_outboundTag = "direct"
            elseif default_node_id == "_blackhole" then
                default_outboundTag = "blackhole"
            else
                local default_node = uci:get_all(appname, default_node_id)
                local main_node_id = node.main_node or "nil"
                local proxy = 0
                local proxy_tag
                if main_node_id ~= "nil" then
                    local main_node = uci:get_all(appname, main_node_id)
                    if main_node and api.is_normal_node(main_node) and main_node_id ~= default_node_id then
                        local main_node_outbound = gen_outbound(main_node, "main")
                        if main_node_outbound then
                            table.insert(outbounds, main_node_outbound)
                            proxy = 1
                            proxy_tag = "main"
                            if default_node.type ~= "V2ray" and default_node.type ~= "Xray" then
                                proxy_tag = nil
                                new_port = get_new_port()
                                table.insert(inbounds, {
                                    tag = "proxy_default",
                                    listen = "127.0.0.1",
                                    port = new_port,
                                    protocol = "dokodemo-door",
                                    settings = {network = "tcp,udp", address = default_node.address, port = tonumber(default_node.port)}
                                })
                                if default_node.tls_serverName == nil then
                                    default_node.tls_serverName = default_node.address
                                end
                                default_node.address = "127.0.0.1"
                                default_node.port = new_port
                                table.insert(rules, 1, {
                                    type = "field",
                                    inboundTag = {"proxy_default"},
                                    outboundTag = "main"
                                })
                            end
                        end
                    end
                end
                if default_node and api.is_normal_node(default_node) then
                    local default_outbound = gen_outbound(default_node, "default", { proxy = proxy, tag = proxy_tag })
                    if default_outbound then
                        table.insert(outbounds, default_outbound)
                        default_outboundTag = "default"
                    end
                end
            end

            uci:foreach(appname, "shunt_rules", function(e)
                local name = e[".name"]
                if name and e.remarks then
                    local _node_id = node[name] or "nil"
                    local proxy_tag = node[name .. "_proxy_tag"] or "nil"
                    local outboundTag
                    if _node_id == "_direct" then
                        outboundTag = "direct"
                    elseif _node_id == "_blackhole" then
                        outboundTag = "blackhole"
                    elseif _node_id == "_default" then
                        outboundTag = "default"
                    else
                        if _node_id ~= "nil" then
                            local _node = uci:get_all(appname, _node_id)
                            if _node and api.is_normal_node(_node) then
                                local new_outbound
                                for index, value in ipairs(outbounds) do
                                    if value["_flag_tag"] == _node_id and value["_flag_proxy_tag"] == proxy_tag then
                                        new_outbound = api.clone(value)
                                        break
                                    end
                                end
                                if new_outbound then
                                    new_outbound["tag"] = name
                                    table.insert(outbounds, new_outbound)
                                    outboundTag = name
                                else
                                    if _node.type ~= "V2ray" and _node.type ~= "Xray" then
                                        if proxy_tag ~= "nil" then
                                            new_port = get_new_port()
                                            table.insert(inbounds, {
                                                tag = "proxy_" .. name,
                                                listen = "127.0.0.1",
                                                port = new_port,
                                                protocol = "dokodemo-door",
                                                settings = {network = "tcp,udp", address = _node.address, port = tonumber(_node.port)}
                                            })
                                            if _node.tls_serverName == nil then
                                                _node.tls_serverName = _node.address
                                            end
                                            _node.address = "127.0.0.1"
                                            _node.port = new_port
                                            table.insert(rules, 1, {
                                                type = "field",
                                                inboundTag = {"proxy_" .. name},
                                                outboundTag = proxy_tag
                                            })
                                        end
                                    end
                                    local _outbound = gen_outbound(_node, name, { proxy = (proxy_tag ~= "nil") and 1 or 0, tag = (proxy_tag ~= "nil") and proxy_tag or nil })
                                    if _outbound then
                                        table.insert(outbounds, _outbound)
                                        outboundTag = name
                                    end
                                end
                            end
                        end
                    end
                    if outboundTag then
                        if outboundTag == "default" then 
                            outboundTag = default_outboundTag
                        end
                        local protocols = nil
                        if e["protocol"] and e["protocol"] ~= "" then
                            protocols = {}
                            string.gsub(e["protocol"], '[^' .. " " .. ']+', function(w)
                                table.insert(protocols, w)
                            end)
                        end
                        local domains = nil
                        if e.domain_list then
                            domains = {}
                            string.gsub(e.domain_list, '[^' .. "\r\n" .. ']+', function(w)
                                table.insert(domains, w)
                                if outboundTag == "direct" then
                                    table.insert(dns_direct_domains, w)
                                end
                            end)
                        end
                        local ip = nil
                        if e.ip_list then
                            ip = {}
                            string.gsub(e.ip_list, '[^' .. "\r\n" .. ']+', function(w)
                                table.insert(ip, w)
                                if outboundTag == "direct" then
                                    table.insert(dns_direct_expectIPs, w)
                                end
                            end)
                        end
                        local source = nil
                        if e.source then
                            source = {}
                            string.gsub(e.source, '[^' .. " " .. ']+', function(w)
                                table.insert(source, w)
                            end)
                        end
                        local rule = {
                            type = "field",
                            outboundTag = outboundTag,
                            network = e["network"] or "tcp,udp",
                            source = source,
                            sourcePort = e["sourcePort"] ~= "" and e["sourcePort"] or nil,
                            port = e["port"] ~= "" and e["port"] or nil,
                            protocol = protocols
                        }
                        if domains then
                            local _rule = api.clone(rule)
                            _rule.domains = domains
                            table.insert(rules, _rule)
                        end
                        if ip then
                            local _rule = api.clone(rule)
                            _rule.ip = ip
                            table.insert(rules, _rule)
                        end
                        if not domains and not ip then
                            table.insert(rules, rule)
                        end
                    end
                end
            end)

            if default_outboundTag then 
                table.insert(rules, {
                    type = "field",
                    outboundTag = default_outboundTag,
                    network = "tcp,udp"
                })
            end

            routing = {
                domainStrategy = node.domainStrategy or "AsIs",
                domainMatcher = node.domainMatcher or "hybrid",
                rules = rules
            }
        elseif node.protocol == "_balancing" then
            if node.balancing_node then
                local nodes = node.balancing_node
                local length = #nodes
                for i = 1, length do
                    local node = uci:get_all(appname, nodes[i])
                    local outbound = gen_outbound(node)
                    if outbound then table.insert(outbounds, outbound) end
                end
                routing = {
                    domainStrategy = node.domainStrategy or "AsIs",
                    domainMatcher = node.domainMatcher or "hybrid",
                    balancers = {{tag = "balancer", selector = nodes}},
                    rules = {
                        {type = "field", network = "tcp,udp", balancerTag = "balancer"}
                    }
                }
            end
        else
            local outbound = gen_outbound(node)
            if outbound then table.insert(outbounds, outbound) end
            routing = {
                domainStrategy = "AsIs",
                domainMatcher = "hybrid",
                rules = {}
            }
        end

    end
end

if dns_server or dns_fakedns then
    local rules = {}

    dns = {
        tag = "dns-in1",
        disableCache = (dns_cache and dns_cache == "0") and true or false,
        disableFallback = true,
        disableFallbackIfMatch = true,
        servers = {
            dns_server
        },
        clientIp = (dns_client_ip and dns_client_ip ~= "") and dns_client_ip or nil,
        queryStrategy = (dns_query_strategy and dns_query_strategy ~= "") and dns_query_strategy or nil
    }
    if doh_url and doh_host then
        dns.hosts = {
            [doh_host] = dns_server
        }
        dns.servers = {
            doh_url
        }
    end

    if dns_tcp_server then
        dns.servers = {
            dns_tcp_server
        }
    end

    if dns_fakedns then
        fakedns = {}
        fakedns[#fakedns + 1] = {
            ipPool = "198.18.0.0/16",
            poolSize = 65535
        }
        dns_server = "1.1.1.1"
        dns.servers = {
            "fakedns"
        }
    end

    local nodes_domain = {}
    local nodes_domain_text = sys.exec('uci show passwall2 | grep ".address=" | cut -d "\'" -f 2 | grep "[a-zA-Z]$" | sort -u')
    string.gsub(nodes_domain_text, '[^' .. "\r\n" .. ']+', function(w)
        table.insert(nodes_domain, w)
        table.insert(dns_direct_domains, w)
    end)

    table.insert(dns.servers, {
        address = local_dns_address,
        port = tonumber(local_dns_port),
        domains = #dns_direct_domains > 0 and dns_direct_domains or nil,
        --expectIPs = #dns_direct_expectIPs > 0 and dns_direct_expectIPs or nil
    })

    if dns_listen_port then
        table.insert(inbounds, {
            listen = "127.0.0.1",
            port = tonumber(dns_listen_port),
            protocol = "dokodemo-door",
            tag = "dns-in",
            settings = {
                address = dns_server,
                port = 53,
                network = "tcp,udp"
            }
        })
    end

    table.insert(rules, {
        type = "field",
        inboundTag = {
            "dns-in"
        },
        outboundTag = "dns-out"
    })

    if node_id and redir_port and not dns_fakedns then
        local outboundTag = node_id
        local node = uci:get_all(appname, node_id)
        if node.protocol == "_shunt" then
            outboundTag = "default"
        end
        table.insert(rules, {
            type = "field",
            inboundTag = {
                "dns-in1"
            },
            outboundTag = outboundTag
        })
    end

    if nodes_domain and #nodes_domain > 0 then
        table.insert(rules, {
            type = "field",
            domains = nodes_domain,
            outboundTag = "direct"
        })
    end

    table.insert(rules, {
        type = "field",
        ip = {
            local_dns_ip
        },
        outboundTag = "direct"
    })
    
    if not routing then
        routing = {
            domainStrategy = "IPOnDemand",
            rules = rules
        }
    else
        for index, value in ipairs(rules) do
            table.insert(routing.rules, 1, value)
        end
    end
end

if inbounds or outbounds then
    local config = {
        log = {
            --access = string.format("/tmp/etc/%s/%s_access.log", appname, "global"),
            --error = string.format("/tmp/etc/%s/%s_error.log", appname, "global"),
            --dnsLog = true,
            loglevel = loglevel
        },
        -- DNS
        dns = dns,
        fakedns = fakedns,
        -- 传入连接
        inbounds = inbounds,
        -- 传出连接
        outbounds = outbounds,
        -- 路由
        routing = routing,
        -- 本地策略
        --[[
        policy = {
            levels = {
                [0] = {
                    handshake = 4,
                    connIdle = 300,
                    uplinkOnly = 2,
                    downlinkOnly = 5,
                    bufferSize = 10240,
                    statsUserUplink = false,
                    statsUserDownlink = false
                }
            },
            system = {
                statsInboundUplink = false,
                statsInboundDownlink = false
            }
        }
        ]]--
    }
    table.insert(outbounds, {
        protocol = "dns",
        tag = "dns-out"
    })
    table.insert(outbounds, {
        protocol = "freedom",
        tag = "direct",
        settings = {
            domainStrategy = "UseIPv4"
        },
        streamSettings = {
            sockopt = {
                mark = 255
            }
        }
    })
    table.insert(outbounds, {
        protocol = "blackhole",
        tag = "blackhole"
    })
    print(jsonc.stringify(config, 1))
end
