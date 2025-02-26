#!/usr/bin/lua

------------------------------------------------
-- @author William Chan <root@williamchan.me>
------------------------------------------------
require 'luci.util'
require 'luci.jsonc'
require 'luci.sys'
local appname = 'passwall'
local api = require ("luci.passwall.api")
local datatypes = require "luci.cbi.datatypes"

-- these global functions are accessed all the time by the event handler
-- so caching them is worth the effort
local tinsert = table.insert
local ssub, slen, schar, sbyte, sformat, sgsub = string.sub, string.len, string.char, string.byte, string.format, string.gsub
local split = api.split
local jsonParse, jsonStringify = luci.jsonc.parse, luci.jsonc.stringify
local base64Decode = api.base64Decode
local uci = api.uci
local fs = api.fs
uci:revert(appname)

local has_ss = api.is_finded("ss-redir")
local has_ss_rust = api.is_finded("sslocal")
local has_trojan_plus = api.is_finded("trojan-plus")
local has_singbox = api.finded_com("singbox")
local has_xray = api.finded_com("xray")
local has_hysteria2 = api.finded_com("hysteria")
local allowInsecure_default = nil
local ss_type_default = uci:get(appname, "@global_subscribe[0]", "ss_type") or "shadowsocks-libev"
local trojan_type_default = uci:get(appname, "@global_subscribe[0]", "trojan_type") or "trojan-plus"
local vmess_type_default = uci:get(appname, "@global_subscribe[0]", "vmess_type") or "xray"
local vless_type_default = uci:get(appname, "@global_subscribe[0]", "vless_type") or "xray"
local hysteria2_type_default = uci:get(appname, "@global_subscribe[0]", "hysteria2_type") or "hysteria2"
local domain_strategy_default = uci:get(appname, "@global_subscribe[0]", "domain_strategy") or ""
local domain_strategy_node = ""
-- 判断是否过滤节点关键字
local filter_keyword_mode_default = uci:get(appname, "@global_subscribe[0]", "filter_keyword_mode") or "0"
local filter_keyword_discard_list_default = uci:get(appname, "@global_subscribe[0]", "filter_discard_list") or {}
local filter_keyword_keep_list_default = uci:get(appname, "@global_subscribe[0]", "filter_keep_list") or {}
local function is_filter_keyword(value)
	if filter_keyword_mode_default == "1" then
		for k,v in ipairs(filter_keyword_discard_list_default) do
			if value:find(v, 1, true) then
				return true
			end
		end
	elseif filter_keyword_mode_default == "2" then
		local result = true
		for k,v in ipairs(filter_keyword_keep_list_default) do
			if value:find(v, 1, true) then
				result = false
			end
		end
		return result
	elseif filter_keyword_mode_default == "3" then
		local result = false
		for k,v in ipairs(filter_keyword_discard_list_default) do
			if value:find(v, 1, true) then
				result = true
			end
		end
		for k,v in ipairs(filter_keyword_keep_list_default) do
			if value:find(v, 1, true) then
				result = false
			end
		end
		return result
	elseif filter_keyword_mode_default == "4" then
		local result = true
		for k,v in ipairs(filter_keyword_keep_list_default) do
			if value:find(v, 1, true) then
				result = false
			end
		end
		for k,v in ipairs(filter_keyword_discard_list_default) do
			if value:find(v, 1, true) then
				result = true
			end
		end
		return result
	end
	return false
end

local nodeResult = {} -- update result
local isDebug = false

local log = function(...)
	if isDebug == true then
		local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
		print(result)
	else
		api.log(...)
	end
end

local nodes_table = {}
for k, e in ipairs(api.get_valid_nodes()) do
	if e.node_type == "normal" then
		nodes_table[#nodes_table + 1] = e
	end
end

-- 获取各项动态配置的当前服务器，可以用 get 和 set， get必须要获取到节点表
local CONFIG = {}
do
	local function import_config(protocol)
		local name = string.upper(protocol)
		local szType = "@global[0]"
		local option = protocol .. "_node"
		
		local node_id = uci:get(appname, szType, option)
		CONFIG[#CONFIG + 1] = {
			log = true,
			remarks = name .. "节点",
			currentNode = node_id and uci:get_all(appname, node_id) or nil,
			set = function(o, server)
				uci:set(appname, szType, option, server)
				o.newNodeId = server
			end
		}
	end
	import_config("tcp")
	import_config("udp")

	if true then
		local i = 0
		local option = "node"
		uci:foreach(appname, "socks", function(t)
			i = i + 1
			local id = t[".name"]
			local node_id = t[option]
			CONFIG[#CONFIG + 1] = {
				log = true,
				id = id,
				remarks = "Socks节点列表[" .. i .. "]",
				currentNode = node_id and uci:get_all(appname, node_id) or nil,
				set = function(o, server)
					if not server or server == "" then
						if #nodes_table > 0 then
							server = nodes_table[1][".name"]
						end
					end
					uci:set(appname, t[".name"], option, server)
					o.newNodeId = server
				end
			}
			if t.autoswitch_backup_node and #t.autoswitch_backup_node > 0 then
				local flag = "Socks节点列表[" .. i .. "]备用节点的列表"
				local currentNodes = {}
				local newNodes = {}
				for k, node_id in ipairs(t.autoswitch_backup_node) do
					if node_id then
						local currentNode = uci:get_all(appname, node_id) or nil
						if currentNode then
							currentNodes[#currentNodes + 1] = {
								log = true,
								remarks = flag .. "[" .. k .. "]",
								currentNode = currentNode,
								set = function(o, server)
									if server and server ~= "nil" then
										table.insert(o.newNodes, server)
									end
								end
							}
						end
					end
				end
				CONFIG[#CONFIG + 1] = {
					remarks = flag,
					currentNodes = currentNodes,
					newNodes = newNodes,
					set = function(o, newNodes)
						if o then
							if not newNodes then newNodes = o.newNodes end
							uci:set_list(appname, id, "autoswitch_backup_node", newNodes or {})
						end
					end
				}
			end
		end)
	end

	if true then
		local i = 0
		local option = "lbss"
		local function is_ip_port(str)
			return str:match("^%d+%.%d+%.%d+%.%d+:%d+$") ~= nil
		end
		uci:foreach(appname, "haproxy_config", function(t)
			i = i + 1
			local node_id = t[option]
			CONFIG[#CONFIG + 1] = {
				log = true,
				id = t[".name"],
				remarks = "HAProxy负载均衡节点列表[" .. i .. "]",
				currentNode = node_id and uci:get_all(appname, node_id) or nil,
				set = function(o, server)
					-- 如果当前 lbss 值不是 ip:port 格式，才进行修改
					if not is_ip_port(t[option]) then
						uci:set(appname, t[".name"], option, server)
						o.newNodeId = server
					end
				end,
				delete = function(o)
					-- 如果当前 lbss 值不是 ip:port 格式，才进行删除
					if not is_ip_port(t[option]) then
						uci:delete(appname, t[".name"])
					end
				end
			}
		end)
	end

	if true then
		local i = 0
		local options = {"tcp", "udp"}
		uci:foreach(appname, "acl_rule", function(t)
			i = i + 1
			for index, value in ipairs(options) do
				local option = value .. "_node"
				local node_id = t[option]
				CONFIG[#CONFIG + 1] = {
					log = true,
					id = t[".name"],
					remarks = "访问控制列表[" .. i .. "]",
					currentNode = node_id and uci:get_all(appname, node_id) or nil,
					set = function(o, server)
						uci:set(appname, t[".name"], option, server)
						o.newNodeId = server
					end
				}
			end
		end)
	end

	uci:foreach(appname, "nodes", function(node)
		local node_id = node[".name"]
		if node.protocol and node.protocol == '_shunt' then
			local rules = {}
			uci:foreach(appname, "shunt_rules", function(e)
				if e[".name"] and e.remarks then
					table.insert(rules, e)
				end
			end)
			table.insert(rules, {
				[".name"] = "default_node",
				remarks = "默认"
			})
			table.insert(rules, {
				[".name"] = "main_node",
				remarks = "默认前置"
			})

			for k, e in pairs(rules) do
				local _node_id = node[e[".name"]] or nil
				if _node_id and api.parseURL(_node_id) then
				else
					CONFIG[#CONFIG + 1] = {
						log = false,
						currentNode = _node_id and uci:get_all(appname, _node_id) or nil,
						remarks = "分流" .. e.remarks .. "节点",
						set = function(o, server)
							if not server then server = "" end
							uci:set(appname, node_id, e[".name"], server)
							o.newNodeId = server
						end
					}
				end
			end
		elseif node.protocol and node.protocol == '_balancing' then
			local flag = "Xray负载均衡节点[" .. node_id .. "]列表"
			local currentNodes = {}
			local newNodes = {}
			if node.balancing_node then
				for k, node in pairs(node.balancing_node) do
					currentNodes[#currentNodes + 1] = {
						log = false,
						node = node,
						currentNode = node and uci:get_all(appname, node) or nil,
						remarks = node,
						set = function(o, server)
							if o and server and server ~= "nil" then
								table.insert(o.newNodes, server)
							end
						end
					}
				end
			end
			CONFIG[#CONFIG + 1] = {
				remarks = flag,
				currentNodes = currentNodes,
				newNodes = newNodes,
				set = function(o, newNodes)
					if o then
						if not newNodes then newNodes = o.newNodes end
						uci:set_list(appname, node_id, "balancing_node", newNodes or {})
					end
				end
			}

			--后备节点
			local currentNode = uci:get_all(appname, node_id) or nil
			if currentNode and currentNode.fallback_node then
				CONFIG[#CONFIG + 1] = {
					log = true,
					id = node_id,
					remarks = "Xray负载均衡节点[" .. node_id .. "]后备节点",
					currentNode = uci:get_all(appname, currentNode.fallback_node) or nil,
					set = function(o, server)
						uci:set(appname, node_id, "fallback_node", server)
						o.newNodeId = server
					end,
					delete = function(o)
						uci:delete(appname, node_id, "fallback_node")
					end
				}
			end
		elseif node.protocol and node.protocol == '_urltest' then
			local flag = "Sing-Box URLTest节点[" .. node_id .. "]列表"
			local currentNodes = {}
			local newNodes = {}
			if node.urltest_node then
				for k, node in pairs(node.urltest_node) do
					currentNodes[#currentNodes + 1] = {
						log = false,
						node = node,
						currentNode = node and uci:get_all(appname, node) or nil,
						remarks = node,
						set = function(o, server)
							if o and server and server ~= "nil" then
								table.insert(o.newNodes, server)
							end
						end
					}
				end
			end
			CONFIG[#CONFIG + 1] = {
				remarks = flag,
				currentNodes = currentNodes,
				newNodes = newNodes,
				set = function(o, newNodes)
					if o then
						if not newNodes then newNodes = o.newNodes end
						uci:set_list(appname, node_id, "urltest_node", newNodes or {})
					end
				end
			}
		else
			--前置代理节点
			local currentNode = uci:get_all(appname, node_id) or nil
			if currentNode and currentNode.preproxy_node then
				CONFIG[#CONFIG + 1] = {
					log = true,
					id = node_id,
					remarks = "节点[" .. node_id .. "]前置代理节点",
					currentNode = uci:get_all(appname, currentNode.preproxy_node) or nil,
					set = function(o, server)
						uci:set(appname, node_id, "preproxy_node", server)
						o.newNodeId = server
					end,
					delete = function(o)
						uci:delete(appname, node_id, "preproxy_node")
					end
				}
			end
			--落地节点
			local currentNode = uci:get_all(appname, node_id) or nil
			if currentNode and currentNode.to_node then
				CONFIG[#CONFIG + 1] = {
					log = true,
					id = node_id,
					remarks = "节点[" .. node_id .. "]落地节点",
					currentNode = uci:get_all(appname, currentNode.to_node) or nil,
					set = function(o, server)
						uci:set(appname, node_id, "to_node", server)
						o.newNodeId = server
					end,
					delete = function(o)
						uci:delete(appname, node_id, "to_node")
					end
				}
			end
		end
	end)

	for k, v in pairs(CONFIG) do
		if v.currentNodes and type(v.currentNodes) == "table" then
			for kk, vv in pairs(v.currentNodes) do
				if vv.currentNode == nil then
					CONFIG[k].currentNodes[kk] = nil
				end
			end
		else
			if v.currentNode == nil then
				if v.delete then
					v.delete()
				end
				CONFIG[k] = nil
			end
		end
	end
end

-- urlencode
-- local function get_urlencode(c) return sformat("%%%02X", sbyte(c)) end

-- local function urlEncode(szText)
-- 	local str = szText:gsub("([^0-9a-zA-Z ])", get_urlencode)
-- 	str = str:gsub(" ", "+")
-- 	return str
-- end

local function get_urldecode(h) return schar(tonumber(h, 16)) end
local function UrlDecode(szText)
	return (szText and szText:gsub("+", " "):gsub("%%(%x%x)", get_urldecode)) or nil
end

-- trim
local function trim(text)
	if not text or text == "" then return "" end
	return (sgsub(text, "^%s*(.-)%s*$", "%1"))
end

-- 取机场信息（剩余流量、到期时间）
local subscribe_info = {}
local function get_subscribe_info(cfgid, value)
	if type(cfgid) ~= "string" or cfgid == "" or type(value) ~= "string" then
		return
	end
	value = value:gsub("%s+", "")
	local expired_date = value:match("套餐到期：(.+)")
	local rem_traffic = value:match("剩余流量：(.+)")
	subscribe_info[cfgid] = subscribe_info[cfgid] or {expired_date = "", rem_traffic = ""}
	if expired_date then
		subscribe_info[cfgid]["expired_date"] = expired_date
	end
	if rem_traffic then
		subscribe_info[cfgid]["rem_traffic"] = rem_traffic
	end
end

-- 处理数据
local function processData(szType, content, add_mode, add_from)
	--log(content, add_mode, add_from)
	local result = {
		timeout = 60,
		add_mode = add_mode, --0为手动配置,1为导入,2为订阅
		add_from = add_from
	}
	--ssr://base64(host:port:protocol:method:obfs:base64pass/?obfsparam=base64param&protoparam=base64param&remarks=base64remarks&group=base64group&udpport=0&uot=0)
	if szType == 'ssr' then
		result.type = "SSR"

		local dat = split(content, "/%?")
		local hostInfo = split(dat[1], ':')
		if dat[1]:match('%[(.*)%]') then
			result.address = dat[1]:match('%[(.*)%]')
		else
			result.address = hostInfo[#hostInfo-5]
		end
		result.port = hostInfo[#hostInfo-4]
		result.protocol = hostInfo[#hostInfo-3]
		result.method = hostInfo[#hostInfo-2]
		result.obfs = hostInfo[#hostInfo-1]
		result.password = base64Decode(hostInfo[#hostInfo])	
		local params = {}
		for _, v in pairs(split(dat[2], '&')) do
			local t = split(v, '=')
			params[t[1]] = t[2]
		end
		result.obfs_param = base64Decode(params.obfsparam)
		result.protocol_param = base64Decode(params.protoparam)
		local group = base64Decode(params.group)
		if group then result.group = group end
		result.remarks = base64Decode(params.remarks)
	elseif szType == 'vmess' then
		local info = jsonParse(content)
		if has_singbox then
			result.type = 'sing-box'
		end
		if has_xray then
			result.type = 'Xray'
		end
		if vmess_type_default == "sing-box" and has_singbox then
			result.type = 'sing-box'
		end
		if vmess_type_default == "xray" and has_xray then
			result.type = "Xray"
		end
		result.alter_id = info.aid
		result.address = info.add
		result.port = info.port
		result.protocol = 'vmess'
		result.uuid = info.id
		result.remarks = info.ps
		-- result.mux = 1
		-- result.mux_concurrency = 8

		if not info.net then info.net = "tcp" end
		info.net = string.lower(info.net)
		if result.type == "sing-box" and info.net == "raw" then 
			info.net = "tcp"
		elseif result.type == "Xray" and info.net == "tcp" then
			info.net = "raw"
		end
		if info.net == "splithttp" then info.net = "xhttp" end
		if info.net == 'h2' or info.net == 'http' then
			info.net = "http"
			result.transport = (result.type == "Xray") and "xhttp" or "http"
		else
			result.transport = info.net
		end
		if info.net == 'ws' then
			result.ws_host = info.host
			result.ws_path = info.path
			if result.type == "sing-box" and info.path then
				local ws_path_dat = split(info.path, "?")
				local ws_path = ws_path_dat[1]
				local ws_path_params = {}
				for _, v in pairs(split(ws_path_dat[2], '&')) do
					local t = split(v, '=')
					ws_path_params[t[1]] = t[2]
				end
				if ws_path_params.ed and tonumber(ws_path_params.ed) then
					result.ws_path = ws_path
					result.ws_enableEarlyData = "1"
					result.ws_maxEarlyData = tonumber(ws_path_params.ed)
					result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
				end
			end
		end
		if info.net == "http" then
			if result.type == "Xray" then
				result.xhttp_mode = "stream-one"
				result.xhttp_host = info.host
				result.xhttp_path = info.path
			else
				result.http_host = info.host
				result.http_path = info.path
			end
		end
		if info.net == 'raw' or info.net == 'tcp' then
			if info.type and info.type ~= "http" then
				info.type = "none"
			end
			result.tcp_guise = info.type
			result.tcp_guise_http_host = info.host
			result.tcp_guise_http_path = info.path
		end
		if info.net == 'kcp' or info.net == 'mkcp' then
			info.net = "mkcp"
			result.mkcp_guise = info.type
			result.mkcp_mtu = 1350
			result.mkcp_tti = 50
			result.mkcp_uplinkCapacity = 5
			result.mkcp_downlinkCapacity = 20
			result.mkcp_readBufferSize = 2
			result.mkcp_writeBufferSize = 2
			result.mkcp_seed = info.seed
		end
		if info.net == 'quic' then
			result.quic_guise = info.type
			result.quic_key = info.key
			result.quic_security = info.securty
		end
		if info.net == 'grpc' then
			result.grpc_serviceName = info.path
		end
		if info.net == 'xhttp' then
			result.xhttp_host = info.host
			result.xhttp_path = info.path
		end
		if info.net == 'httpupgrade' then
			result.httpupgrade_host = info.host
			result.httpupgrade_path = info.path
		end
		if not info.security then result.security = "auto" end
		if info.tls == "tls" or info.tls == "1" then
			result.tls = "1"
			result.tls_serverName = (info.sni and info.sni ~= "") and info.sni or info.host
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		else
			result.tls = "0"
		end

		if result.type == "sing-box" and (result.transport == "mkcp" or result.transport == "xhttp" or result.transport == "splithttp") then
			log("跳过节点:" .. result.remarks .."，因Sing-Box不支持" .. szType .. "协议的" .. result.transport .. "传输方式，需更换Xray。")
			return nil
		end
	elseif szType == "ss" then
		result.type = "SS"

		--SS-URI = "ss://" userinfo "@" hostname ":" port [ "/" ] [ "?" plugin ] [ "#" tag ]
		--userinfo = websafe-base64-encode-utf8(method  ":" password)
		--ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1
		--ss://cmM0LW1kNTpwYXNzd2Q@192.168.100.1:8888/?plugin=obfs-local%3Bobfs%3Dhttp#Example2
		--ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888#Example3
		--ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@192.168.100.1:8888/?plugin=v2ray-plugin%3Bserver#Example3
		--ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0ZXN0@xxxxxx.com:443?type=ws&path=%2Ftestpath&host=xxxxxx.com&security=tls&fp=&alpn=h3%2Ch2%2Chttp%2F1.1&sni=xxxxxx.com#test-1%40ss
		--ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp4eHh4eHhAeHh4eC54eHh4eC5jb206NTYwMDE#Hong%20Kong-01

		local idx_sp = 0
		local alias = ""
		if content:find("#") then
			idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
		end
		result.remarks = UrlDecode(alias)
		local info = content:sub(1, idx_sp - 1):gsub("/%?", "?")
		local params = {}
		if info:find("?") then
			local find_index = info:find("?")
			local query = split(info, "?")
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				params[t[1]] = UrlDecode(t[2])
			end
			if params.plugin then
				local plugin_info = params.plugin
				local idx_pn = plugin_info:find(";")
				if idx_pn then
					result.plugin = plugin_info:sub(1, idx_pn - 1)
					result.plugin_opts =
						plugin_info:sub(idx_pn + 1, #plugin_info)
				else
					result.plugin = plugin_info
				end
			end
			if result.plugin and result.plugin == "simple-obfs" then
				result.plugin = "obfs-local"
			end
			info = info:sub(1, find_index - 1)
		end

		local hostInfo = split(base64Decode(UrlDecode(info)), "@")
		if hostInfo and #hostInfo > 0 then
			local host_port = hostInfo[#hostInfo]
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				result.port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			local userinfo = nil
			if #hostInfo > 2 then
				userinfo = {}
				for i = 1, #hostInfo - 1 do
					tinsert(userinfo, hostInfo[i])
				end
				userinfo = table.concat(userinfo, '@')
			else
				userinfo = base64Decode(hostInfo[1])
			end

			local method = userinfo:sub(1, userinfo:find(":") - 1)
			local password = userinfo:sub(userinfo:find(":") + 1, #userinfo)
			result.method = method
			result.password = password

			if ss_type_default == "shadowsocks-rust" and has_ss_rust then
				result.type = 'SS-Rust'
			end
			if ss_type_default == "xray" and has_xray then
				result.type = 'Xray'
				result.protocol = 'shadowsocks'
				result.transport = 'raw'
			end
			if ss_type_default == "sing-box" and has_singbox then
				result.type = 'sing-box'
				result.protocol = 'shadowsocks'
			end

			if result.type ~= "Xray" then
				result.method = (method:lower() == "chacha20-poly1305" and "chacha20-ietf-poly1305") or
						(method:lower() == "xchacha20-poly1305" and "xchacha20-ietf-poly1305") or method
			end

			if result.plugin then
				if result.type == 'Xray' then
					--不支持插件
					result.error_msg = "Xray不支持插件."
				end
				if result.type == "sing-box" then
					result.plugin_enabled = "1"
				end
			end

			if result.type == "SS" then
				local aead2022_methods = { "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305" }
				local aead2022 = false
				for k, v in ipairs(aead2022_methods) do
					if method:lower() == v:lower() then
						aead2022 = true
					end
				end
				if aead2022 then
					-- shadowsocks-libev 不支持2022加密
					result.error_msg = "shadowsocks-libev 不支持2022加密."
				end
			end

			if params.type then
				params.type = string.lower(params.type)
				if result.type == "sing-box" and params.type == "raw" then 
					params.type = "tcp"
				elseif result.type == "Xray" and params.type == "tcp" then
					params.type = "raw"
				end
				if params.type == "h2" or params.type == "http" then
					params.type = "http"
					result.transport = (result.type == "Xray") and "xhttp" or "http"
				else
					result.transport = params.type
				end
				if result.type ~= "SS-Rust" and result.type ~= "SS" then
					if params.type == 'ws' then
						result.ws_host = params.host
						result.ws_path = params.path
						if result.type == "sing-box" and params.path then
							local ws_path_dat = split(params.path, "?")
							local ws_path = ws_path_dat[1]
							local ws_path_params = {}
							for _, v in pairs(split(ws_path_dat[2], '&')) do
								local t = split(v, '=')
								ws_path_params[t[1]] = t[2]
							end
							if ws_path_params.ed and tonumber(ws_path_params.ed) then
								result.ws_path = ws_path
								result.ws_enableEarlyData = "1"
								result.ws_maxEarlyData = tonumber(ws_path_params.ed)
								result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
							end
						end
					end
					if params.type == "http" then
						if result.type == "sing-box" then
							result.transport = "http"
							result.http_host = params.host
							result.http_path = params.path
						elseif result.type == "Xray" then
							result.transport = "xhttp"
							result.xhttp_mode = "stream-one"
							result.xhttp_host = params.host
							result.xhttp_path = params.path
						end
					end
					if params.type == 'raw' or params.type == 'tcp' then
						result.tcp_guise = params.headerType or "none"
						result.tcp_guise_http_host = params.host
						result.tcp_guise_http_path = params.path
					end
					if params.type == 'kcp' or params.type == 'mkcp' then
						result.transport = "mkcp"
						result.mkcp_guise = params.headerType or "none"
						result.mkcp_mtu = 1350
						result.mkcp_tti = 50
						result.mkcp_uplinkCapacity = 5
						result.mkcp_downlinkCapacity = 20
						result.mkcp_readBufferSize = 2
						result.mkcp_writeBufferSize = 2
						result.mkcp_seed = params.seed
					end
					if params.type == 'quic' then
						result.quic_guise = params.headerType or "none"
						result.quic_key = params.key
						result.quic_security = params.quicSecurity or "none"
					end
					if params.type == 'grpc' then
						if params.path then result.grpc_serviceName = params.path end
						if params.serviceName then result.grpc_serviceName = params.serviceName end
						result.grpc_mode = params.mode or "gun"
					end
					result.tls = "0"
					if params.security == "tls" or params.security == "reality" then
						result.tls = "1"
						result.tls_serverName = (params.sni and params.sni ~= "") and params.sni or params.host
						result.alpn = params.alpn
						result.fingerprint = (params.fp and params.fp ~= "") and params.fp or "chrome"
						if params.security == "reality" then
							result.reality = "1"
							result.reality_publicKey = params.pbk or nil
							result.reality_shortId = params.sid or nil
							result.reality_spiderX = params.spx or nil
						end
					end
					result.tls_allowInsecure = allowInsecure_default and "1" or "0"
				else
					result.error_msg = "请更换Xray或Sing-Box来支持SS更多的传输方式."
				end
			end
		end
	elseif szType == "trojan" then
		if trojan_type_default == "trojan-plus" and has_trojan_plus then
			result.type = "Trojan-Plus"
		elseif trojan_type_default == "sing-box" and has_singbox then
			result.type = 'sing-box'
		elseif trojan_type_default == "xray" and has_xray then
			result.type = 'Xray'
		end
		result.protocol = 'trojan'
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.password = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local query = split(Info[2], "?")
			local host_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				if #t > 1 then
					params[string.lower(t[1])] = UrlDecode(t[2])
				end
			end
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			local peer, sni = nil, ""
			if params.peer then peer = params.peer end
			sni = params.sni and params.sni or ""
			result.port = port

			result.tls = '1'
			result.tls_serverName = peer and peer or sni

			if params.allowinsecure then
				if params.allowinsecure == "1" or params.allowinsecure == "0" then
					result.tls_allowInsecure = params.allowinsecure
				else
					result.tls_allowInsecure = string.lower(params.allowinsecure) == "true" and "1" or "0"
				end
				--log(result.remarks .. ' 使用节点AllowInsecure设定: '.. result.tls_allowInsecure)
			else
				result.tls_allowInsecure = allowInsecure_default and "1" or "0"
			end

			if not params.type then params.type = "tcp" end
			params.type = string.lower(params.type)
			if result.type == "sing-box" and params.type == "raw" then 
				params.type = "tcp"
			elseif result.type == "Xray" and params.type == "tcp" then
				params.type = "raw"
			end
			if params.type == "h2" or params.type == "http" then
				params.type = "http"
				result.transport = (result.type == "Xray") and "xhttp" or "http"
			else
				result.transport = params.type
			end
			if params.type == 'ws' then
				result.ws_host = params.host
				result.ws_path = params.path
				if result.type == "sing-box" and params.path then
					local ws_path_dat = split(params.path, "?")
					local ws_path = ws_path_dat[1]
					local ws_path_params = {}
					for _, v in pairs(split(ws_path_dat[2], '&')) do
						local t = split(v, '=')
						ws_path_params[t[1]] = t[2]
					end
					if ws_path_params.ed and tonumber(ws_path_params.ed) then
						result.ws_path = ws_path
						result.ws_enableEarlyData = "1"
						result.ws_maxEarlyData = tonumber(ws_path_params.ed)
						result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
					end
				end
			end
			if params.type == "http" then
				if result.type == "sing-box" then
					result.transport = "http"
					result.http_host = params.host
					result.http_path = params.path
				elseif result.type == "Xray" then
					result.transport = "xhttp"
					result.xhttp_mode = "stream-one"
					result.xhttp_host = params.host
					result.xhttp_path = params.path
				end
			end
			if params.type == 'raw' or params.type == 'tcp' then
				result.tcp_guise = params.headerType or "none"
				result.tcp_guise_http_host = params.host
				result.tcp_guise_http_path = params.path
			end
			if params.type == 'kcp' or params.type == 'mkcp' then
				result.transport = "mkcp"
				result.mkcp_guise = params.headerType or "none"
				result.mkcp_mtu = 1350
				result.mkcp_tti = 50
				result.mkcp_uplinkCapacity = 5
				result.mkcp_downlinkCapacity = 20
				result.mkcp_readBufferSize = 2
				result.mkcp_writeBufferSize = 2
				result.mkcp_seed = params.seed
			end
			if params.type == 'quic' then
				result.quic_guise = params.headerType or "none"
				result.quic_key = params.key
				result.quic_security = params.quicSecurity or "none"
			end
			if params.type == 'grpc' then
				if params.path then result.grpc_serviceName = params.path end
				if params.serviceName then result.grpc_serviceName = params.serviceName end
				result.grpc_mode = params.mode or "gun"
			end
			if params.type == 'xhttp' or params.type == 'splithttp' then
				result.xhttp_host = params.host
				result.xhttp_path = params.path
			end
			if params.type == 'httpupgrade' then
				result.httpupgrade_host = params.host
				result.httpupgrade_path = params.path
			end

			result.encryption = params.encryption or "none"

			result.flow = params.flow or nil

			if result.type == "sing-box" and (result.transport == "mkcp" or result.transport == "xhttp" or result.transport == "splithttp") then
				log("跳过节点:" .. result.remarks .."，因Sing-Box不支持" .. szType .. "协议的" .. result.transport .. "传输方式，需更换Xray。")
				return nil
			end
		end

	elseif szType == "ssd" then
		result.type = "SS"
		result.address = content.server
		result.port = content.port
		result.password = content.password
		result.method = content.encryption
		result.plugin = content.plugin
		result.plugin_opts = content.plugin_options
		result.group = content.airport
		result.remarks = content.remarks
	elseif szType == "vless" then
		if has_singbox then
			result.type = 'sing-box'
		end
		if has_xray then
			result.type = 'Xray'
		end
		if vless_type_default == "sing-box" and has_singbox then
			result.type = 'sing-box'
		end
		if vless_type_default == "xray" and has_xray then
			result.type = "Xray"
		end
		result.protocol = "vless"
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		if content:find("@") then
			local Info = split(content, "@")
			result.uuid = UrlDecode(Info[1])
			local port = "443"
			Info[2] = (Info[2] or ""):gsub("/%?", "?")
			local query = split(Info[2], "?")
			local host_port = query[1]
			local params = {}
			for _, v in pairs(split(query[2], '&')) do
				local t = split(v, '=')
				params[t[1]] = UrlDecode(t[2])
			end
			-- [2001:4860:4860::8888]:443
			-- 8.8.8.8:443
			if host_port:find(":") then
				local sp = split(host_port, ":")
				port = sp[#sp]
				if api.is_ipv6addrport(host_port) then
					result.address = api.get_ipv6_only(host_port)
				else
					result.address = sp[1]
				end
			else
				result.address = host_port
			end

			if not params.type then params.type = "tcp" end
			params.type = string.lower(params.type)
			if result.type == "sing-box" and params.type == "raw" then 
				params.type = "tcp"
			elseif result.type == "Xray" and params.type == "tcp" then
				params.type = "raw"
			end
			if params.type == "splithttp" then params.type = "xhttp" end
			if params.type == "h2" or params.type == "http" then
				params.type = "http"
				result.transport = (result.type == "Xray") and "xhttp" or "http"
			else
				result.transport = params.type
			end
			if params.type == 'ws' then
				result.ws_host = params.host
				result.ws_path = params.path
				if result.type == "sing-box" and params.path then
					local ws_path_dat = split(params.path, "?")
					local ws_path = ws_path_dat[1]
					local ws_path_params = {}
					for _, v in pairs(split(ws_path_dat[2], '&')) do
						local t = split(v, '=')
						ws_path_params[t[1]] = t[2]
					end
					if ws_path_params.ed and tonumber(ws_path_params.ed) then
						result.ws_path = ws_path
						result.ws_enableEarlyData = "1"
						result.ws_maxEarlyData = tonumber(ws_path_params.ed)
						result.ws_earlyDataHeaderName = "Sec-WebSocket-Protocol"
					end
				end
			end
			if params.type == "http" then
				if result.type == "sing-box" then
					result.transport = "http"
					result.http_host = params.host
					result.http_path = params.path
				elseif result.type == "Xray" then
					result.transport = "xhttp"
					result.xhttp_mode = "stream-one"
					result.xhttp_host = params.host
					result.xhttp_path = params.path
				end
			end
			if params.type == 'raw' or params.type == 'tcp' then
				result.tcp_guise = params.headerType or "none"
				result.tcp_guise_http_host = params.host
				result.tcp_guise_http_path = params.path
			end
			if params.type == 'kcp' or params.type == 'mkcp' then
				result.transport = "mkcp"
				result.mkcp_guise = params.headerType or "none"
				result.mkcp_mtu = 1350
				result.mkcp_tti = 50
				result.mkcp_uplinkCapacity = 5
				result.mkcp_downlinkCapacity = 20
				result.mkcp_readBufferSize = 2
				result.mkcp_writeBufferSize = 2
				result.mkcp_seed = params.seed
			end
			if params.type == 'quic' then
				result.quic_guise = params.headerType or "none"
				result.quic_key = params.key
				result.quic_security = params.quicSecurity or "none"
			end
			if params.type == 'grpc' then
				if params.path then result.grpc_serviceName = params.path end
				if params.serviceName then result.grpc_serviceName = params.serviceName end
				result.grpc_mode = params.mode or "gun"
			end
			if params.type == 'xhttp' then
				result.xhttp_host = params.host
				result.xhttp_path = params.path
				result.xhttp_mode = params.mode or "auto"
				result.use_xhttp_extra = (params.extra and params.extra ~= "") and "1" or nil
				result.xhttp_extra = (params.extra and params.extra ~= "") and params.extra or nil
				local success, Data = pcall(jsonParse, params.extra)
				if success and Data then
					local address = (Data.extra and Data.extra.downloadSettings and Data.extra.downloadSettings.address)
							or (Data.downloadSettings and Data.downloadSettings.address)
					result.download_address = address and address ~= "" and address or nil
				else
					result.download_address = nil
				end
			end
			if params.type == 'httpupgrade' then
				result.httpupgrade_host = params.host
				result.httpupgrade_path = params.path
			end
			
			result.encryption = params.encryption or "none"

			result.flow = params.flow or nil

			result.tls = "0"
			if params.security == "tls" or params.security == "reality" then
				result.tls = "1"
				result.tls_serverName = (params.sni and params.sni ~= "") and params.sni or params.host
				result.alpn = params.alpn
				result.fingerprint = (params.fp and params.fp ~= "") and params.fp or "chrome"
				if params.security == "reality" then
					result.reality = "1"
					result.reality_publicKey = params.pbk or nil
					result.reality_shortId = params.sid or nil
					result.reality_spiderX = params.spx or nil
				end
			end

			result.port = port
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"

			if result.type == "sing-box" and (result.transport == "mkcp" or result.transport == "xhttp" or result.transport == "splithttp") then
				log("跳过节点:" .. result.remarks .."，因Sing-Box不支持" .. szType .. "协议的" .. result.transport .. "传输方式，需更换Xray。")
				return nil
			end
		end
	elseif szType == 'hysteria' then
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		
		local dat = split(content:gsub("/%?", "?"), '%?')
		local host_port = dat[1]
		local params = {}
		for _, v in pairs(split(dat[2], '&')) do
			local t = split(v, '=')
			if #t > 0 then
				params[t[1]] = t[2]
			end
		end
		-- [2001:4860:4860::8888]:443
		-- 8.8.8.8:443
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.protocol = params.protocol
		result.hysteria_obfs = params.obfsParam
		result.hysteria_auth_type = "string"
		result.hysteria_auth_password = params.auth
		result.tls_serverName = params.peer
		if params.insecure and (params.insecure == "1" or params.insecure == "0") then
			result.tls_allowInsecure = params.insecure
			--log(result.remarks ..' 使用节点AllowInsecure设定: '.. result.tls_allowInsecure)
		else
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		end
		result.hysteria_alpn = params.alpn
		result.hysteria_up_mbps = params.upmbps
		result.hysteria_down_mbps = params.downmbps

		if has_singbox then
			result.type = 'sing-box'
			result.protocol = "hysteria"
		end
	elseif szType == 'hysteria2' or szType == 'hy2' then
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		local Info = content
		if content:find("@") then
			local contents = split(content, "@")
			result.hysteria2_auth_password = UrlDecode(contents[1])
			Info = (contents[2] or ""):gsub("/%?", "?")
		end
		local query = split(Info, "?")
		local host_port = query[1]
		local params = {}
		for _, v in pairs(split(query[2], '&')) do
			local t = split(v, '=')
			if #t > 1 then
				params[string.lower(t[1])] = UrlDecode(t[2])
			end
		end
		-- [2001:4860:4860::8888]:443
		-- 8.8.8.8:443
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.tls_serverName = params.sni
		if params.insecure and (params.insecure == "1" or params.insecure == "0") then
			result.tls_allowInsecure = params.insecure
			--log(result.remarks ..' 使用节点AllowInsecure设定: '.. result.tls_allowInsecure)
		else
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		end
		result.hysteria2_tls_pinSHA256 = params.pinSHA256

		if has_hysteria2 then
			result.type = "Hysteria2"
			if params["obfs-password"] then
				result.hysteria2_obfs = params["obfs-password"]
			end
		end
		if hysteria2_type_default == "sing-box" and has_singbox then
			result.type = 'sing-box'
			result.protocol = "hysteria2"
			if params["obfs-password"] then
				result.hysteria2_obfs_type = "salamander"
				result.hysteria2_obfs_password = params["obfs-password"]
			end
		end
	elseif szType == 'tuic' then
		local alias = ""
		if content:find("#") then
			local idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
			content = content:sub(0, idx_sp - 1)
		end
		result.remarks = UrlDecode(alias)
		local Info = content
		if content:find("@") then
			local contents = split(content, "@")
			if contents[1]:find(":") then
				local userinfo = split(contents[1], ":")
				result.uuid = UrlDecode(userinfo[1])
				result.password = UrlDecode(userinfo[2])
			end
			Info = (contents[2] or ""):gsub("/%?", "?")
		end
		local query = split(Info, "?")
		local host_port = query[1]
		local params = {}
		for _, v in pairs(split(query[2], '&')) do
			local t = split(v, '=')
			if #t > 1 then
				params[string.lower(t[1])] = UrlDecode(t[2])
			end
		end
		if host_port:find(":") then
			local sp = split(host_port, ":")
			result.port = sp[#sp]
			if api.is_ipv6addrport(host_port) then
				result.address = api.get_ipv6_only(host_port)
			else
				result.address = sp[1]
			end
		else
			result.address = host_port
		end
		result.tls_serverName = params.sni
		result.tuic_alpn = params.alpn or "default"
		result.tuic_congestion_control = params.congestion_control or "cubic"
		if params.allowinsecure then
			if params.allowinsecure == "1" or params.allowinsecure == "0" then
				result.tls_allowInsecure = params.allowinsecure
			else
				result.tls_allowInsecure = string.lower(params.allowinsecure) == "true" and "1" or "0"
			end
			--log(result.remarks .. ' 使用节点AllowInsecure设定: '.. result.tls_allowInsecure)
		else
			result.tls_allowInsecure = allowInsecure_default and "1" or "0"
		end
		result.type = 'sing-box'
		result.protocol = "tuic"
	else
		log('暂时不支持' .. szType .. "类型的节点订阅，跳过此节点。")
		return nil
	end
	if not result.remarks or result.remarks == "" then
		if result.address and result.port then
			result.remarks = result.address .. ':' .. result.port
		else
			result.remarks = "NULL"
		end
	end
	return result
end

local function curl(url, file, ua, mode)
	local curl_args = api.clone(api.curl_args)
	if ua and ua ~= "" and ua ~= "curl" then
		table.insert(curl_args, '--user-agent "' .. ua .. '"')
	end
	local return_code
	if mode == "direct" then
		return_code = api.curl_direct(url, file, curl_args)
	elseif mode == "proxy" then
		return_code = api.curl_proxy(url, file, curl_args)
	else
		return_code = api.curl_auto(url, file, curl_args)
	end
	return return_code
end

local function truncate_nodes(add_from)
	for _, config in pairs(CONFIG) do
		if config.currentNodes and #config.currentNodes > 0 then
			local newNodes = {}
			local removeNodesSet = {}
			for k, v in pairs(config.currentNodes) do
				if v.currentNode and v.currentNode.add_mode == "2" then
					if (not add_from) or (add_from and add_from == v.currentNode.add_from) then
						removeNodesSet[v.currentNode[".name"]] = true
					end
				end
			end
			for _, value in ipairs(config.currentNodes) do
				if not removeNodesSet[value.currentNode[".name"]] then
					newNodes[#newNodes + 1] = value.currentNode[".name"]
				end
			end
			if config.set then
				config.set(config, newNodes)
			end
		else
			if config.currentNode and config.currentNode.add_mode == "2" then
				if (not add_from) or (add_from and add_from == config.currentNode.add_from) then
					if config.delete then
						config.delete(config)
					elseif config.set then
						config.set(config, "")
					end
				end
			end
		end
	end
	uci:foreach(appname, "nodes", function(node)
		if node.add_mode == "2" then
			if (not add_from) or (add_from and add_from == node.add_from) then
				uci:delete(appname, node['.name'])
			end
		end
	end)
	uci:foreach(appname, "subscribe_list", function(o)
		if (not add_from) or add_from == o.remark then
			uci:delete(appname, o['.name'], "md5")
		end
	end)
	api.uci_save(uci, appname, true)
end

local function select_node(nodes, config, parentConfig)
	if config.currentNode then
		local server
		-- 特别优先级 cfgid
		if config.currentNode[".name"] then
			for index, node in pairs(nodes) do
				if node[".name"] == config.currentNode[".name"] then
					log('更新【' .. config.remarks .. '】匹配节点：' .. node.remarks)
					server = node[".name"]
					break
				end
			end
		end
		-- 第一优先级 类型 + 备注 + IP + 端口
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.type and config.currentNode.remarks and config.currentNode.address and config.currentNode.port then
					if node.type and node.remarks and node.address and node.port then
						if node.type == config.currentNode.type and node.remarks == config.currentNode.remarks and (node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port) then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第一匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第二优先级 类型 + IP + 端口
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.type and config.currentNode.address and config.currentNode.port then
					if node.type and node.address and node.port then
						if node.type == config.currentNode.type and (node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port) then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第二匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第三优先级 IP + 端口
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.address and config.currentNode.port then
					if node.address and node.port then
						if node.address .. ':' .. node.port == config.currentNode.address .. ':' .. config.currentNode.port then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第三匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第四优先级 IP
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.address then
					if node.address then
						if node.address == config.currentNode.address then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第四匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		-- 第五优先级备注
		if not server then
			for index, node in pairs(nodes) do
				if config.currentNode.remarks then
					if node.remarks then
						if node.remarks == config.currentNode.remarks then
							if config.log == nil or config.log == true then
								log('更新【' .. config.remarks .. '】第五匹配节点：' .. node.remarks)
							end
							server = node[".name"]
							break
						end
					end
				end
			end
		end
		if not parentConfig then
			-- 还不行 随便找一个
			if not server then
				if #nodes_table > 0 then
					if config.log == nil or config.log == true then
						log('【' .. config.remarks .. '】' .. '无法找到最匹配的节点，当前已更换为：' .. nodes_table[1].remarks)
					end
					server = nodes_table[1][".name"]
				end
			end
		end
		if server then
			if parentConfig then
				config.set(parentConfig, server)
			else
				config.set(config, server)
			end
		end
	else
		if not parentConfig then
			config.set(config, "")
		end
	end
end

local function update_node(manual)
	if next(nodeResult) == nil then
		log("没有可用的节点信息更新。")
		return
	end

	local group = {}
	for _, v in ipairs(nodeResult) do
		group[v["remark"]] = true
	end

	if manual == 0 and next(group) then
		uci:foreach(appname, "nodes", function(node)
			-- 如果未发现新节点或手动导入的节点就不要删除了...
			if node.add_mode == "2" and (node.add_from and group[node.add_from] == true) then
				uci:delete(appname, node['.name'])
			end
		end)
	end
	for _, v in ipairs(nodeResult) do
		local remark = v["remark"]
		local list = v["list"]
		for _, vv in ipairs(list) do
			local cfgid = uci:section(appname, "nodes", api.gen_short_uuid())
			for kkk, vvv in pairs(vv) do
				uci:set(appname, cfgid, kkk, vvv)
				-- sing-box 域名解析策略
				if kkk == "type" and vvv == "sing-box" then
					uci:set(appname, cfgid, "domain_strategy", domain_strategy_node)
				end
			end
		end
	end
	-- 更新机场信息
	for cfgid, info in pairs(subscribe_info) do
		for key, value in pairs(info) do
			if value ~= "" then
				uci:set(appname, cfgid, key, value)
			else
				uci:delete(appname, cfgid, key)
			end
		end
	end
	api.uci_save(uci, appname, true)

	if next(CONFIG) then
		local nodes = {}
		uci:foreach(appname, "nodes", function(node)
			nodes[#nodes + 1] = node
		end)

		for _, config in pairs(CONFIG) do
			if config.currentNodes and #config.currentNodes > 0 then
				for kk, vv in pairs(config.currentNodes) do
					select_node(nodes, vv, config)
				end
				config.set(config)
			else
				select_node(nodes, config)
			end
		end

		api.uci_save(uci, appname, true)
	end

	if arg[3] == "cron" then
		if not fs.access("/var/lock/" .. appname .. ".lock") then
			luci.sys.call("touch /tmp/lock/" .. appname .. "_cron.lock")
		end
	end

	luci.sys.call("/etc/init.d/" .. appname .. " restart > /dev/null 2>&1 &")
end

local function parse_link(raw, add_mode, add_from, cfgid)
	if raw and #raw > 0 then
		local nodes, szType
		local node_list = {}
		-- SSD 似乎是这种格式 ssd:// 开头的
		if raw:find('ssd://') then
			szType = 'ssd'
			local nEnd = select(2, raw:find('ssd://'))
			nodes = base64Decode(raw:sub(nEnd + 1, #raw))
			nodes = jsonParse(nodes)
			local extra = {
				airport = nodes.airport,
				port = nodes.port,
				encryption = nodes.encryption,
				password = nodes.password
			}
			local servers = {}
			-- SS里面包着 干脆直接这样
			for _, server in ipairs(nodes.servers) do
				tinsert(servers, setmetatable(server, { __index = extra }))
			end
			nodes = servers
		else
			-- ssd 外的格式
			if add_mode == "1" then
				nodes = split(raw:gsub(" ", "\n"), "\n")
			else
				nodes = split(base64Decode(raw):gsub(" ", "\n"), "\n")
			end
		end

		for _, v in ipairs(nodes) do
			if v then
				xpcall(function ()
					local result
					if szType == 'ssd' then
						result = processData(szType, v, add_mode, add_from)
					elseif not szType then
						local node = trim(v)
						local dat = split(node, "://")
						if dat and dat[1] and dat[2] then
							if dat[1] == 'ss' or dat[1] == 'trojan' then
								result = processData(dat[1], dat[2], add_mode, add_from)
							else
								result = processData(dat[1], base64Decode(dat[2]), add_mode, add_from)
							end
						end
					else
						log('跳过未知类型: ' .. szType)
					end
					-- log(result)
					if result then
						if result.error_msg then
							log('丢弃节点: ' .. result.remarks .. ", 原因:" .. result.error_msg)
						elseif not result.type then
							log('丢弃节点: ' .. result.remarks .. ", 找不到可使用二进制.")
						elseif (add_mode == "2" and is_filter_keyword(result.remarks)) or not result.address or result.remarks == "NULL" or result.address == "127.0.0.1" or
								(not datatypes.hostname(result.address) and not (api.is_ip(result.address))) then
							log('丢弃过滤节点: ' .. result.type .. ' 节点, ' .. result.remarks)
						else
							tinsert(node_list, result)
						end
						if add_mode == "2" then
							get_subscribe_info(cfgid, result.remarks)
						end
					end
				end, function (err)
					--log(err)
					log(v, "解析错误，跳过此节点。")
				end
			)
			end
		end
		if #node_list > 0 then
			nodeResult[#nodeResult + 1] = {
				remark = add_from,
				list = node_list
			}
		end
		log('成功解析【' .. add_from .. '】节点数量: ' .. #node_list)
	else
		if add_mode == "2" then
			log('获取到的【' .. add_from .. '】订阅内容为空，可能是订阅地址失效，或是网络问题，请请检测。')
		end
	end
end

local execute = function()
	do
		local subscribe_list = {}
		local fail_list = {}
		if arg[2] then
			string.gsub(arg[2], '[^' .. "," .. ']+', function(w)
				subscribe_list[#subscribe_list + 1] = uci:get_all(appname, w) or {}
			end)
		else
			uci:foreach(appname, "subscribe_list", function(o)
				subscribe_list[#subscribe_list + 1] = o
			end)
		end

		for index, value in ipairs(subscribe_list) do
			local cfgid = value[".name"]
			local remark = value.remark
			local url = value.url
			if value.allowInsecure and value.allowInsecure == "1" then
				allowInsecure_default = true
			end
			local filter_keyword_mode = value.filter_keyword_mode or "5"
			if filter_keyword_mode == "0" then
				filter_keyword_mode_default = "0"
			elseif filter_keyword_mode == "1" then
				filter_keyword_mode_default = "1"
				filter_keyword_discard_list_default = value.filter_discard_list or {}
			elseif filter_keyword_mode == "2" then
				filter_keyword_mode_default = "2"
				filter_keyword_keep_list_default = value.filter_keep_list or {}
			elseif filter_keyword_mode == "3" then
				filter_keyword_mode_default = "3"
				filter_keyword_keep_list_default = value.filter_keep_list or {}
				filter_keyword_discard_list_default = value.filter_discard_list or {}
			elseif filter_keyword_mode == "4" then
				filter_keyword_mode_default = "4"
				filter_keyword_keep_list_default = value.filter_keep_list or {}
				filter_keyword_discard_list_default = value.filter_discard_list or {}
			end
			local ss_type = value.ss_type or "global"
			if ss_type ~= "global" then
				ss_type_default = ss_type
			end
			local trojan_type = value.trojan_type or "global"
			if trojan_type ~= "global" then
				trojan_type_default = trojan_type
			end
			local vmess_type = value.vmess_type or "global"
			if vmess_type ~= "global" then
				vmess_type_default = vmess_type
			end
			local vless_type = value.vless_type or "global"
			if vless_type ~= "global" then
				vless_type_default = vless_type
			end
			local hysteria2_type = value.hysteria2_type or "global"
			if hysteria2_type ~= "global" then
				hysteria2_type_default = hysteria2_type
			end
			local domain_strategy = value.domain_strategy or "global"
			if domain_strategy ~= "global" then
				domain_strategy_node = domain_strategy
			else
				domain_strategy_node = domain_strategy_default
			end
			local ua = value.user_agent
			local access_mode = value.access_mode
			local result = (not access_mode) and "自动" or (access_mode == "direct" and "直连访问" or (access_mode == "proxy" and "通过代理" or "自动"))
			log('正在订阅:【' .. remark .. '】' .. url .. ' [' .. result .. ']')
			local tmp_file = "/tmp/" .. cfgid
			local raw = curl(url, tmp_file, ua, access_mode)
			if raw == 0 then
				local f = io.open(tmp_file, "r")
				local stdout = f:read("*all")
				f:close()
				raw = trim(stdout)
				local old_md5 = value.md5 or ""
				local new_md5 = luci.sys.exec("[ -f " .. tmp_file .. " ] && md5sum " .. tmp_file .. " | awk '{print $1}' || echo 0"):gsub("\n", "")
				os.remove(tmp_file)
				if old_md5 == new_md5 then
					log('订阅:【' .. remark .. '】没有变化，无需更新。')
				else
					parse_link(raw, "2", remark, cfgid)
					uci:set(appname, cfgid, "md5", new_md5)
				end
			else
				fail_list[#fail_list + 1] = value
			end
			allowInsecure_default = nil
			filter_keyword_mode_default = uci:get(appname, "@global_subscribe[0]", "filter_keyword_mode") or "0"
			filter_keyword_discard_list_default = uci:get(appname, "@global_subscribe[0]", "filter_discard_list") or {}
			filter_keyword_keep_list_default = uci:get(appname, "@global_subscribe[0]", "filter_keep_list") or {}
			ss_type_default = uci:get(appname, "@global_subscribe[0]", "ss_type") or "shadowsocks-libev"
			trojan_type_default = uci:get(appname, "@global_subscribe[0]", "trojan_type") or "trojan-plus"
			vmess_type_default = uci:get(appname, "@global_subscribe[0]", "vmess_type") or "xray"
			vless_type_default = uci:get(appname, "@global_subscribe[0]", "vless_type") or "xray"
			hysteria2_type_default = uci:get(appname, "@global_subscribe[0]", "hysteria2_type") or "hysteria2"
		end

		if #fail_list > 0 then
			for index, value in ipairs(fail_list) do
				log(string.format('【%s】订阅失败，可能是订阅地址失效，或是网络问题，请诊断！', value.remark))
			end
		end
		update_node(0)
	end
end

if arg[1] then
	if arg[1] == "start" then
		log('开始订阅...')
		xpcall(execute, function(e)
			log(e)
			if type(debug) == "table" and type(debug.traceback) == "function" then
				log(debug.traceback())
			end
			log('发生错误, 正在恢复服务')
		end)
		log('订阅完毕...')
	elseif arg[1] == "add" then
		local f = assert(io.open("/tmp/links.conf", 'r'))
		local content = f:read('*all')
		f:close()
		local nodes = split(content:gsub(" ", "\n"), "\n")
		for _, raw in ipairs(nodes) do
			parse_link(raw, "1", "导入")
		end
		update_node(1)
		luci.sys.call("rm -f /tmp/links.conf")
	elseif arg[1] == "truncate" then
		truncate_nodes(arg[2])
	end
end
