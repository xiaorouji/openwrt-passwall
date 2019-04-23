local i = "passwall"
local d = require "luci.dispatcher"
local ipkg = require("luci.model.ipkg")
local a,t,e

local function is_finded(e)
	return luci.sys.exec("find /usr/*bin -iname "..e.." -type f") ~="" and true or false
end

local function is_installed(e)
	return ipkg.installed(e)
end

local ss_encrypt_method={
"rc4",
"rc4-md5",
"aes-128-cfb",
"aes-192-cfb",
"aes-256-cfb",
"aes-128-ctr",
"aes-192-ctr",
"aes-256-ctr",
"bf-cfb",
"camellia-128-cfb",
"camellia-192-cfb",
"camellia-256-cfb",
"salsa20",
"chacha20",
"chacha20-ietf",
-- aead
"aes-128-gcm",
"aes-192-gcm",
"aes-256-gcm",
"chacha20-ietf-poly1305",
"xchacha20-ietf-poly1305",
}

local ssr_encrypt_method={
"none",
"table",
"rc4",
"rc4-md5",
"rc4-md5-6",
"aes-128-cfb",
"aes-192-cfb",
"aes-256-cfb",
"aes-128-ctr",
"aes-192-ctr",
"aes-256-ctr",
"bf-cfb",
"camellia-128-cfb",
"camellia-192-cfb",
"camellia-256-cfb",
"cast5-cfb",
"des-cfb",
"rc2-cfb",
"seed-cfb",
"salsa20",
"chacha20",
"chacha20-ietf",
}

local ssr_protocol={
"origin",
"verify_simple",
"verify_deflate",
"verify_sha1",
"auth_simple",
"auth_sha1",
"auth_sha1_v2",
"auth_sha1_v4",
"auth_aes128_md5",
"auth_aes128_sha1",
"auth_chain_a",
"auth_chain_b",
"auth_chain_c",
"auth_chain_d",
"auth_chain_e",
"auth_chain_f",
}
local ssr_obfs={
"plain",
"http_simple",
"http_post",
"random_head",
"tls_simple",
"tls1.0_session_auth",
"tls1.2_ticket_auth",
}

local v2ray_security={
"none",
"auto",
"aes-128-gcm",
"chacha20-poly1305",
}

local v2ray_header_type={
"none",
"srtp",
"utp",
"wechat-video",
"dtls",
"wireguard",
}

a=Map(i,translate("ShadowSocks Server Config"),translate("Leave the default false if the server does not support TCP_fastopen and Onetime Authentication."))
a.redirect=d.build_url("admin","vpn","passwall")
t=a:section(NamedSection,arg[1],"servers","")
t.addremove=false
t.dynamic=false
e=t:option(Value,"remarks",translate("Node Remarks"))
e.default=translate("Node Remarks")
e.rmempty=false

serverType=t:option(ListValue,"server_type",translate("Server Type"))
if is_finded("ss-redir") then
serverType:value("SS",translate("Shadowsocks Server"))
end
if is_finded("ssr-redir") then
serverType:value("SSR",translate("ShadowsocksR Server"))
end
if is_installed("v2ray")then
serverType:value("V2ray",translate("V2ray Server"))
end
if is_installed("brook") or is_finded("brook") then
serverType:value("Brook",translate("Brook Server"))
end

e=t:option(ListValue,"v2ray_protocol",translate("V2ray Protocol"))
e:value("vmess",translate("Vmess"))
e:depends("server_type","V2ray")

e.rmempty=false
e=t:option(Value,"server",translate("Server Address"))
e.rmempty=false

e=t:option(Flag,"use_ipv6",translate("Use IPv6"))
e.default=0

e=t:option(Value,"server_port",translate("Server Port"))
e.datatype="port"
e.rmempty=false

e=t:option(Value,"password",translate("Password"))
e.password=true
e.rmempty=false
e:depends("server_type","SS")
e:depends("server_type","SSR")
e:depends("server_type","Brook")

e=t:option(ListValue,"ss_encrypt_method",translate("Encrypt Method"))
for a,t in ipairs(ss_encrypt_method)do e:value(t)end
e:depends("server_type","SS")

e=t:option(ListValue,"ssr_encrypt_method",translate("Encrypt Method"))
for a,t in ipairs(ssr_encrypt_method)do e:value(t)end
e:depends("server_type","SSR")

e=t:option(ListValue,"v2ray_security",translate("Encrypt Method"))
for a,t in ipairs(v2ray_security)do e:value(t)end
e:depends("server_type","V2ray")

e=t:option(ListValue,"protocol",translate("Protocol"))
for a,t in ipairs(ssr_protocol)do e:value(t)end
e:depends("server_type","SSR")

e=t:option(Value,"protocol_param",translate("Protocol_param"))
e:depends("server_type","SSR")

e=t:option(ListValue,"obfs",translate("Obfs"))
for a,t in ipairs(ssr_obfs)do e:value(t)end
e:depends("server_type","SSR")

e=t:option(Value,"obfs_param",translate("Obfs_param"))
e:depends("server_type","SSR")

e=t:option(Value,"timeout",translate("Connection Timeout"))
e.datatype="uinteger"
e.default=300
e.rmempty=false
e:depends("server_type","SS")
e:depends("server_type","SSR")

e=t:option(ListValue,"fast_open",translate("Fast_open"))
e:value("false")
e:value("true")
e.rmempty=false
e:depends("server_type","SS")
e:depends("server_type","SSR")

e=t:option(Flag,"use_kcp",translate("Use Kcptun"),"<span style='color:red'>"..translate("Please confirm whether the Kcptun is installed. If not, please go to Rule Update download installation.").."</span>")
e.default=0
e:depends("server_type","SS")
e:depends("server_type","SSR")
e:depends("server_type","Brook")

e=t:option(Value,"kcp_server",translate("Kcptun Server"))
e.placeholder=translate("Default:Current Server")
e:depends("use_kcp","1")
e=t:option(Flag,"kcp_use_ipv6",translate("Use IPv6"))
e.default=0
e:depends("use_kcp","1")
e=t:option(Value,"kcp_port",translate("Kcptun Port"))
e.datatype="port"
e:depends("use_kcp","1")
e=t:option(TextValue,"kcp_opts",translate("Kcptun Config"),translate("--crypt aes192 --key abc123 --mtu 1350 --sndwnd 128 --rcvwnd 1024 --mode fast"))
e.placeholder="--crypt aes192 --key abc123 --mtu 1350 --sndwnd 128 --rcvwnd 1024 --mode fast"
e:depends("use_kcp","1")

e=t:option(Value,"v2ray_VMess_id",translate("ID"))
e.password=true
e.rmempty=false
e:depends("v2ray_protocol","vmess")

e=t:option(Value,"v2ray_VMess_alterId",translate("Alter ID"))
e.rmempty=false
e:depends("v2ray_protocol","vmess")

e=t:option(Value,"v2ray_VMess_level",translate("User Level"))
e.default=1
e:depends("server_type","V2ray")

e=t:option(ListValue,"v2ray_stream_security",translate("Transport Layer Encryption"),translate('Whether or not transport layer encryption is enabled, the supported options are "none" for unencrypted (default) and "TLS" for using TLS.'))
e:value("none","none")
e:value("tls", "tls")
e:depends("server_type","V2ray")

e=t:option(ListValue,"v2ray_transport",translate("Transport"))
e:value("tcp","TCP")
e:value("mkcp", "mKCP")
e:value("ws", "WebSocket")
e:value("h2", "HTTP/2")
e:value("ds", "DomainSocket")
e:value("quic", "QUIC")
e:depends("server_type","V2ray")

-- [[ TCP部分 ]]--

-- TCP伪装
e = t:option(ListValue, "v2ray_tcp_guise", translate("Camouflage Type"))
e:depends("v2ray_transport", "tcp")
e:value("none", "none")
e:value("http", "http")

-- HTTP域名
e = t:option(DynamicList, "v2ray_tcp_guise_http_host", translate("HTTP Host"))
e:depends("v2ray_tcp_guise", "http")

-- HTTP路径
e = t:option(DynamicList, "v2ray_tcp_guise_http_path", translate("HTTP Path"))
e:depends("v2ray_tcp_guise", "http")

-- [[ mKCP部分 ]]--

e=t:option(ListValue,"v2ray_mkcp_guise",translate("Camouflage Type"))
for a,t in ipairs(v2ray_header_type)do e:value(t)end
e:depends("v2ray_transport","mkcp")

e=t:option(Value,"v2ray_mkcp_mtu",translate("KCP MTU"))
e:depends("v2ray_transport","mkcp")

e=t:option(Value,"v2ray_mkcp_tti",translate("KCP TTI"))
e:depends("v2ray_transport","mkcp")

e=t:option(Value,"v2ray_mkcp_uplinkCapacity",translate("KCP uplinkCapacity"))
e:depends("v2ray_transport","mkcp")

e=t:option(Value,"v2ray_mkcp_downlinkCapacity",translate("KCP downlinkCapacity"))
e:depends("v2ray_transport","mkcp")

e=t:option(Flag,"v2ray_mkcp_congestion",translate("KCP Congestion"))
e:depends("v2ray_transport","mkcp")

e=t:option(Value,"v2ray_mkcp_readBufferSize",translate("KCP readBufferSize"))
e:depends("v2ray_transport","mkcp")

e=t:option(Value,"v2ray_mkcp_writeBufferSize",translate("KCP writeBufferSize"))
e:depends("v2ray_transport","mkcp")

-- [[ WebSocket部分 ]]--

e=t:option(Value,"v2ray_ws_host",translate("WebSocket Host"))
e:depends("v2ray_transport","ws")

e=t:option(Value,"v2ray_ws_path",translate("WebSocket Path"))
e:depends("v2ray_transport","ws")

-- [[ HTTP/2部分 ]]--

e = t:option(DynamicList, "v2ray_h2_host", translate("HTTP/2 Host"))
e:depends("v2ray_transport", "h2")

e = t:option(Value, "v2ray_h2_path", translate("HTTP/2 Path"))
e:depends("v2ray_transport", "h2")

-- [[ DomainSocket部分 ]]--

e=t:option(Value,"v2ray_ds_path","Path", translate("A legal file path. This file must not exist before running V2Ray."))
e:depends("v2ray_transport","ds")

-- [[ QUIC部分 ]]--
e=t:option(ListValue,"v2ray_quic_security",translate("Encrypt Method"))
e:value("none")
e:value("aes-128-gcm")
e:value("chacha20-poly1305")
e:depends("v2ray_transport","quic")

e=t:option(Value,"v2ray_quic_key",translate("Encrypt Method")..translate("Key"))
e:depends("v2ray_transport","quic")

e=t:option(ListValue,"v2ray_quic_guise",translate("Camouflage Type"))
for a,t in ipairs(v2ray_header_type)do e:value(t)end
e:depends("v2ray_transport","quic")

-- [[ 其它 ]]--

e=t:option(Flag,"v2ray_mux",translate("Mux"))
e:depends("server_type","V2ray")

e=t:option(Value,"v2ray_mux_concurrency",translate("Mux Concurrency"))
e.default=8
e:depends("v2ray_mux","1")

--e=t:option(Flag,"v2ray_insecure",translate("allowInsecure"))
--e:depends("server_type","V2ray")

return a
