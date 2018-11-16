local ucursor = require "luci.model.uci"
local json = require "luci.jsonc"
local server_section = arg[1]
local proto = arg[2]
local redir_port = arg[3]
local socks5_proxy_port = arg[4]

local server = ucursor:get_all("passwall", server_section)

local inbound_json={}

if socks5_proxy_port ~="nil" then
	inbound_json = {
		listen = "0.0.0.0",
        port = socks5_proxy_port,
        protocol = "socks",
        settings = {
            auth = "noauth",
            udp = true,
            ip = "127.0.0.1"
        }
    }
end

if redir_port ~="nil" then
	inbound_json = {
        port = redir_port,
        protocol = "dokodemo-door",
        settings = {
            network = proto,
            followRedirect = true
        },
        sniffing = {
            enabled = true,
            destOverride = { "http", "tls" }
        }
    }
end

local v2ray = {
	log = {
		--error = "/var/log/v2ray.log",
		loglevel = "warning"
	},
    -- 传入连接
    inbound = inbound_json,
	
    -- 传出连接
    outbound = {
        protocol = server.v2ray_protocol,
        settings = {
            vnext = {
                {
                    address = server.server,
                    port = tonumber(server.server_port),
                    users = {
                        {
                            id = server.v2ray_VMess_id,
                            alterId = tonumber(server.v2ray_VMess_alterId),
							level = tonumber(server.v2ray_VMess_level),
                            security = server.v2ray_security
                        }
                    }
                }
            }
        },
    -- 底层传输配置
        streamSettings = {
            network = server.v2ray_transport,
            security = (server.v2ray_tls == '1') and "tls" or "none",
            kcpSettings = (server.v2ray_transport == "mkcp") and {
              mtu = tonumber(server.v2ray_mkcp_mtu),
              tti = tonumber(server.v2ray_mkcp_tti),
              uplinkCapacity = tonumber(server.v2ray_mkcp_uplinkCapacity),
              downlinkCapacity = tonumber(server.v2ray_mkcp_downlinkCapacity),
              congestion = (server.v2ray_mkcp_congestion == "1") and true or false,
              readBufferSize = tonumber(server.v2ray_mkcp_readBufferSize),
              writeBufferSize = tonumber(server.v2ray_mkcp_writeBufferSize),
              header = {
                  type = server.v2ray_mkcp_guise
              }
          } or nil,
             wsSettings = (server.v2ray_transport == "ws") and {
                path = server.v2ray_ws_path,
                headers = (server.v2ray_ws_host ~= nil) and {
                    Host = server.v2ray_ws_host
                } or nil,
            } or nil,
            httpSettings = (server.v2ray_transport == "h2") and {
                path = server.v2ray_h2_path,
                host = server.v2ray_h2_host,
            } or nil
        },
        mux = {
            enabled = (server.v2ray_mux == "1") and true or false
      }
    },

    -- 额外传出连接
    outboundDetour = {
        {
            protocol = "freedom",
            tag = "direct",
            settings = { keep = "" }
        }
    }
}
print(json.stringify(v2ray))