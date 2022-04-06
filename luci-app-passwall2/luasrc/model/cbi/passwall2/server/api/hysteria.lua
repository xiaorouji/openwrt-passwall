module("luci.model.cbi.passwall2.server.api.hysteria", package.seeall)
function gen_config(user)
    local config = {
        listen = ":" .. user.port,
        protocol = user.protocol or "udp",
        obfs = user.hysteria_obfs,
        cert = user.tls_certificateFile,
        key = user.tls_keyFile,
        auth = (user.hysteria_auth_type == "string") and {
            mode = "password",
            config = {
                password = user.hysteria_auth_password
            }
        } or nil,
        disable_udp = (user.hysteria_udp == "0") and true or false,
        alpn = user.hysteria_alpn or nil,
        up_mbps = tonumber(user.hysteria_up_mbps) or 10,
        down_mbps = tonumber(user.hysteria_down_mbps) or 50,
        recv_window_conn = (user.hysteria_recv_window_conn) and tonumber(user.hysteria_recv_window_conn) or nil,
        recv_window = (user.hysteria_recv_window) and tonumber(user.hysteria_recv_window) or nil,
        disable_mtu_discovery = (user.hysteria_disable_mtu_discovery) and true or false
    }
    return config
end
