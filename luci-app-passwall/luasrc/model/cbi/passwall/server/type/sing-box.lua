local m, s = ...

local api = require "luci.passwall.api"

local singbox_bin = api.finded_com("singbox")

if not singbox_bin then
	return
end

local singbox_tags = luci.sys.exec(singbox_bin .. " version  | grep 'Tags:' | awk '{print $2}'")

local type_name = "sing-box"

local option_prefix = "singbox_"

local function option_name(name)
	return option_prefix .. name
end

local function rm_prefix_cfgvalue(self, section)
	if self.option:find(option_prefix) == 1 then
		return m:get(section, self.option:sub(1 + #option_prefix))
	end
end
local function rm_prefix_write(self, section, value)
	if s.fields["type"]:formvalue(arg[1]) == type_name then
		if self.option:find(option_prefix) == 1 then
			m:set(section, self.option:sub(1 + #option_prefix), value)
		end
	end
end
local function rm_prefix_remove(self, section, value)
	if s.fields["type"]:formvalue(arg[1]) == type_name then
		if self.option:find(option_prefix) == 1 then
			m:del(section, self.option:sub(1 + #option_prefix))
		end
	end
end

local ss_method_list = {
	"none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
	"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

-- [[ Sing-Box ]]

s.fields["type"]:value(type_name, "Sing-Box")

o = s:option(ListValue, option_name("protocol"), translate("Protocol"))
o:value("socks", "Socks")
o:value("http", "HTTP")
o:value("shadowsocks", "Shadowsocks")
o:value("vmess", "Vmess")
o:value("vless", "VLESS")
o:value("trojan", "Trojan")
o:value("direct", "Direct")

o = s:option(Value, option_name("port"), translate("Listen Port"))
o.datatype = "port"

o = s:option(Flag, option_name("auth"), translate("Auth"))
o.validate = function(self, value, t)
	if value and value == "1" then
		local user_v = s.fields[option_name("username")]:formvalue(t) or ""
		local pass_v = s.fields[option_name("password")]:formvalue(t) or ""
		if user_v == "" or pass_v == "" then
			return nil, translate("Username and Password must be used together!")
		end
	end
	return value
end
o:depends({ [option_name("protocol")] = "socks" })
o:depends({ [option_name("protocol")] = "http" })

o = s:option(Value, option_name("username"), translate("Username"))
o:depends({ [option_name("auth")] = true })

o = s:option(Value, option_name("password"), translate("Password"))
o.password = true
o:depends({ [option_name("auth")] = true })
o:depends({ [option_name("protocol")] = "shadowsocks" })

o = s:option(ListValue, option_name("d_protocol"), translate("Destination protocol"))
o:value("tcp", "TCP")
o:value("udp", "UDP")
o:value("tcp,udp", "TCP,UDP")
o:depends({ [option_name("protocol")] = "direct" })

o = s:option(Value, option_name("d_address"), translate("Destination address"))
o:depends({ [option_name("protocol")] = "direct" })

o = s:option(Value, option_name("d_port"), translate("Destination port"))
o.datatype = "port"
o:depends({ [option_name("protocol")] = "direct" })

o = s:option(Value, option_name("decryption"), translate("Encrypt Method"))
o.default = "none"
o:depends({ [option_name("protocol")] = "vless" })

o = s:option(ListValue, option_name("ss_method"), translate("Encrypt Method"))
o.not_rewrite = true
for a, t in ipairs(ss_method_list) do o:value(t) end
o:depends({ [option_name("protocol")] = "shadowsocks" })
function o.cfgvalue(self, section)
	return m:get(section, "method")
end
function o.write(self, section, value)
	if s.fields["type"]:formvalue(arg[1]) == type_name then
		m:set(section, "method", value)
	end
end

o = s:option(DynamicList, option_name("uuid"), translate("ID") .. "/" .. translate("Password"))
for i = 1, 3 do
	o:value(api.gen_uuid(1))
end
o:depends({ [option_name("protocol")] = "vmess" })
o:depends({ [option_name("protocol")] = "vless" })
o:depends({ [option_name("protocol")] = "trojan" })

o = s:option(ListValue, option_name("flow"), translate("flow"))
o.default = ""
o:value("", translate("Disable"))
o:value("xtls-rprx-vision")
o:depends({ [option_name("protocol")] = "vless" })

o = s:option(Flag, option_name("tls"), translate("TLS"))
o.default = 0
o.validate = function(self, value, t)
	if value then
		if value == "1" then
			local ca = s.fields[option_name("tls_certificateFile")]:formvalue(t) or ""
			local key = s.fields[option_name("tls_keyFile")]:formvalue(t) or ""
			if ca == "" or key == "" then
				return nil, translate("Public key and Private key path can not be empty!")
			end
		end
		return value
	end
end
o:depends({ [option_name("protocol")] = "http" })
o:depends({ [option_name("protocol")] = "shadowsocks" })
o:depends({ [option_name("protocol")] = "vmess" })
o:depends({ [option_name("protocol")] = "vless" })
o:depends({ [option_name("protocol")] = "trojan" })

-- [[ TLS部分 ]] --

o = s:option(FileUpload, option_name("tls_certificateFile"), translate("Public key absolute path"), translate("as:") .. "/etc/ssl/fullchain.pem")
o.default = m:get(s.section, "tls_certificateFile") or "/etc/config/ssl/" .. arg[1] .. ".pem"
o:depends({ [option_name("tls")] = true })
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not nixio.fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end

o = s:option(FileUpload, option_name("tls_keyFile"), translate("Private key absolute path"), translate("as:") .. "/etc/ssl/private.key")
o.default = m:get(s.section, "tls_keyFile") or "/etc/config/ssl/" .. arg[1] .. ".key"
o:depends({ [option_name("tls")] = true })
o.validate = function(self, value, t)
	if value and value ~= "" then
		if not nixio.fs.access(value) then
			return nil, translate("Can't find this file!")
		else
			return value
		end
	end
	return nil
end

o = s:option(ListValue, option_name("transport"), translate("Transport"))
o:value("tcp", "TCP")
o:value("http", "HTTP")
o:value("ws", "WebSocket")
o:value("quic", "QUIC")
o:value("grpc", "gRPC")
o:depends({ [option_name("protocol")] = "shadowsocks" })
o:depends({ [option_name("protocol")] = "vmess" })
o:depends({ [option_name("protocol")] = "vless" })
o:depends({ [option_name("protocol")] = "trojan" })

-- [[ HTTP部分 ]]--

o = s:option(Value, option_name("http_host"), translate("HTTP Host"))
o:depends({ [option_name("transport")] = "http" })

o = s:option(Value, option_name("http_path"), translate("HTTP Path"))
o:depends({ [option_name("transport")] = "http" })

-- [[ WebSocket部分 ]]--

o = s:option(Value, option_name("ws_host"), translate("WebSocket Host"))
o:depends({ [option_name("transport")] = "ws" })

o = s:option(Value, option_name("ws_path"), translate("WebSocket Path"))
o:depends({ [option_name("transport")] = "ws" })

-- [[ gRPC部分 ]]--
o = s:option(Value, option_name("grpc_serviceName"), "ServiceName")
o:depends({ [option_name("transport")] = "grpc" })

o = s:option(Flag, option_name("bind_local"), translate("Bind Local"), translate("When selected, it can only be accessed locally, It is recommended to turn on when using reverse proxies or be fallback."))
o.default = "0"

o = s:option(Flag, option_name("accept_lan"), translate("Accept LAN Access"), translate("When selected, it can accessed lan , this will not be safe!"))
o.default = "0"

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" and e.type == type_name then
		nodes_table[#nodes_table + 1] = {
			id = e[".name"],
			remarks = e["remark"]
		}
	end
end

o = s:option(ListValue, option_name("outbound_node"), translate("outbound node"))
o:value("nil", translate("Close"))
o:value("_socks", translate("Custom Socks"))
o:value("_http", translate("Custom HTTP"))
o:value("_iface", translate("Custom Interface"))
for k, v in pairs(nodes_table) do o:value(v.id, v.remarks) end
o.default = "nil"

o = s:option(Value, option_name("outbound_node_address"), translate("Address (Support Domain Name)"))
o:depends({ [option_name("outbound_node")] = "_socks" })
o:depends({ [option_name("outbound_node")] = "_http" })

o = s:option(Value, option_name("outbound_node_port"), translate("Port"))
o.datatype = "port"
o:depends({ [option_name("outbound_node")] = "_socks" })
o:depends({ [option_name("outbound_node")] = "_http" })

o = s:option(Value, option_name("outbound_node_username"), translate("Username"))
o:depends({ [option_name("outbound_node")] = "_socks" })
o:depends({ [option_name("outbound_node")] = "_http" })

o = s:option(Value, option_name("outbound_node_password"), translate("Password"))
o.password = true
o:depends({ [option_name("outbound_node")] = "_socks" })
o:depends({ [option_name("outbound_node")] = "_http" })

o = s:option(Value, option_name("outbound_node_iface"), translate("Interface"))
o.default = "eth1"
o:depends({ [option_name("outbound_node")] = "_iface" })

o = s:option(Flag, option_name("log"), translate("Log"))
o.default = "1"
o.rmempty = false

o = s:option(ListValue, option_name("loglevel"), translate("Log Level"))
o.default = "info"
o:value("debug")
o:value("info")
o:value("warn")
o:value("error")
o:depends({ [option_name("log")] = true })

for key, value in pairs(s.fields) do
	if key:find(option_prefix) == 1 then
		if not s.fields[key].not_rewrite then
			s.fields[key].cfgvalue = rm_prefix_cfgvalue
			s.fields[key].write = rm_prefix_write
			s.fields[key].remove = rm_prefix_remove
		end

		local deps = s.fields[key].deps
		if #deps > 0 then
			for index, value in ipairs(deps) do
				deps[index]["type"] = type_name
			end
		else
			s.fields[key]:depends({ type = type_name })
		end
	end
end
