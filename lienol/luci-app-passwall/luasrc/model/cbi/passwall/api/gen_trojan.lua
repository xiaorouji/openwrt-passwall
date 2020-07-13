local ucursor = require"luci.model.uci".cursor()
local json = require "luci.jsonc"
local node_section = arg[1]
local run_type = arg[2]
local local_addr = arg[3]
local local_port = arg[4]
local node = ucursor:get_all("passwall", node_section)

local cipher = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA"
local cipher13 = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384"
local trojan = {
    run_type = run_type,
    local_addr = local_addr,
    local_port = tonumber(local_port),
    remote_addr = node.address,
    remote_port = tonumber(node.port),
    password = {node.password},
    log_level = 1,
    ssl = {
        verify = (node.tls_allowInsecure ~= "1") and true or false,
        verify_hostname = true,
        cert = node.trojan_cert_path,
        cipher =  node.fingerprint == nil and cipher or (node.fingerprint == "disable" and cipher13 .. ":" .. cipher or ""),
        cipher_tls13 = node.fingerprint == nil and cipher13 or nil,
        sni = node.tls_serverName,
        alpn = (node.trojan_ws == "1") and {} or {"h2", "http/1.1"},
        reuse_session = true,
        session_ticket = (node.tls_sessionTicket == "1") and true or false,
        fingerprint = (node.fingerprint ~= nil and node.fingerprint ~= "disable" ) and node.fingerprint or "",
        curves = ""
    },
    udp_timeout = 60,
    mux = (node.v2ray_mux == "1") and {
        enabled = true,
        concurrency = tonumber(node.v2ray_mux_concurrency),
        idle_timeout = 60,
        } or nil,
    websocket = (node.trojan_ws == "1") and {
        enabled = true,
        path = (node.v2ray_ws_path ~= nil) and node.v2ray_ws_path or "/",
        host = (node.v2ray_ws_host ~= nil) and node.v2ray_ws_host or (node.tls_serverName ~= nil and node.tls_serverName or node.address)
        } or nil,
    shadowsocks = (node.ss_aead == "1") and {
        enabled = true,
        method = (node.ss_aead_method ~= nil) and node.ss_aead_method or "AEAD_AES_128_GCM",
        password = (node.ss_aead_pwd ~= nil) and node.ss_aead_pwd or ""
        } or nil,
    tcp = {
        no_delay = true,
        keep_alive = true,
        reuse_port = true,
        fast_open = (node.tcp_fast_open == "true") and true or false,
        fast_open_qlen = 20
    }
}
print(json.stringify(trojan, 1))
