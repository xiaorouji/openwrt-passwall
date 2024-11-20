require "luci.sys"
local api = require "luci.passwall.api"
local appname = "passwall"

local var = api.get_args(arg)
local FLAG = var["-FLAG"]
local SMARTDNS_CONF = var["-SMARTDNS_CONF"]
local LOCAL_GROUP = var["-LOCAL_GROUP"]
local REMOTE_GROUP = var["-REMOTE_GROUP"]
local REMOTE_PROXY_SERVER = var["-REMOTE_PROXY_SERVER"]
local REMOTE_EXCLUDE = var["-REMOTE_EXCLUDE"]
local TUN_DNS = var["-TUN_DNS"]
local TCP_NODE = var["-TCP_NODE"]
local USE_DIRECT_LIST = var["-USE_DIRECT_LIST"]
local USE_PROXY_LIST = var["-USE_PROXY_LIST"]
local USE_BLOCK_LIST = var["-USE_BLOCK_LIST"]
local USE_GFW_LIST = var["-USE_GFW_LIST"]
local CHN_LIST = var["-CHN_LIST"]
local DEFAULT_PROXY_MODE = var["-DEFAULT_PROXY_MODE"]
local NO_PROXY_IPV6 = var["-NO_PROXY_IPV6"]
local NO_LOGIC_LOG = var["-NO_LOGIC_LOG"]
local NFTFLAG = var["-NFTFLAG"]
local CACHE_PATH = api.CACHE_PATH
local CACHE_FLAG = "smartdns_" .. FLAG
local CACHE_DNS_PATH = CACHE_PATH .. "/" .. CACHE_FLAG
local CACHE_DNS_FILE = CACHE_DNS_PATH .. ".conf"
local CACHE_TEXT_FILE = CACHE_DNS_PATH .. ".txt"

local uci = api.uci
local sys = api.sys
local fs = api.fs
local datatypes = api.datatypes

local list1 = {}
local excluded_domain = {}
local excluded_domain_str = "!"

local function log(...)
	if NO_LOGIC_LOG == "1" then
		return
	end
	api.log(...)
end

local function check_ipset(domain, ipset)
	if domain == "" or domain:find("#") then
		return false
	end
	if not ipset then
		return
	end
	for k,v in ipairs(list1[domain].ipsets) do
		if ipset == v then
			return true
		end
	end
	return false
end

local function set_domain_extra_param(domain, param)
	if domain == "" or domain:find("#") then
		return
	end
	if not list1[domain] then
		list1[domain] = {
			params = {}
		}
	end
	if not list1[domain].params then
		list1[domain].params = {}
	end
	if not list1[domain].params[param] then
		list1[domain].params[param] = param
	end
end

local function set_domain_address(domain, address)
	if domain == "" or domain:find("#") then
		return
	end
	if not list1[domain] then
		list1[domain] = {}
	end
	if not list1[domain].address then
		list1[domain].address = address
	end
end

local function set_domain_group(domain, group)
	if domain == "" or domain:find("#") then
		return
	end
	if not group then
		return
	end
	if not list1[domain] then
		list1[domain] = {}
	end
	if not list1[domain].group then
		list1[domain].group = group
		if group == REMOTE_GROUP then
			list1[domain].speed_check_mode = "none"
		end
	end
end

local function set_domain_ipset(domain, ipset)
	if domain == "" or domain:find("#") then
		return
	end
	if not ipset then
		return
	end
	if not list1[domain] then
		list1[domain] = {}
	end
	if not list1[domain].ipsets then
		list1[domain].ipsets = {}
	end
	for line in string.gmatch(ipset, '[^' .. "," .. ']+') do
		if not check_ipset(domain, line) then
			table.insert(list1[domain].ipsets, line)
		end
	end
end

local function add_excluded_domain(domain)
	if domain == "" or domain:find("#") then
		return
	end
	table.insert(excluded_domain, domain)
	excluded_domain_str = excluded_domain_str .. "|" .. domain
end

local function check_excluded_domain(domain)
	if domain == "" or domain:find("#") then
		return false
	end
	for k,v in ipairs(excluded_domain) do
		if domain:find(v) then
			return true
		end
	end
	return false
end

local cache_text = ""
local nodes_address_md5 = luci.sys.exec("echo -n $(uci show passwall | grep '\\.address') | md5sum")
local new_rules = luci.sys.exec("echo -n $(find /usr/share/passwall/rules -type f | xargs md5sum)")
local new_text = SMARTDNS_CONF .. LOCAL_GROUP .. REMOTE_GROUP .. REMOTE_PROXY_SERVER .. REMOTE_EXCLUDE .. TUN_DNS .. USE_DIRECT_LIST .. USE_PROXY_LIST .. USE_BLOCK_LIST .. USE_GFW_LIST .. CHN_LIST .. DEFAULT_PROXY_MODE .. NO_PROXY_IPV6 .. nodes_address_md5 .. new_rules
if fs.access(CACHE_TEXT_FILE) then
	for line in io.lines(CACHE_TEXT_FILE) do
		cache_text = line
	end
end

if cache_text ~= new_text then
	api.remove(CACHE_DNS_PATH .. "*")
end

if LOCAL_GROUP == "nil" then
	LOCAL_GROUP = nil
end

if not REMOTE_GROUP or REMOTE_GROUP == "nil" then
	REMOTE_GROUP = "passwall_proxy"
	if TUN_DNS then
		TUN_DNS = TUN_DNS:gsub("#", ":")
	end
	sys.call('sed -i "/passwall/d" /etc/smartdns/custom.conf >/dev/null 2>&1')
end

if not fs.access(CACHE_DNS_FILE) then
	sys.exec(string.format('echo "server %s -bootstrap-dns" >> %s', "114.114.114.114", CACHE_DNS_FILE))
	local proxy_server_name = "passwall-proxy-server"
	sys.call(string.format('echo "proxy-server socks5://%s -name %s" >> %s', REMOTE_PROXY_SERVER, proxy_server_name, CACHE_DNS_FILE))
	if true then
		string.gsub(TUN_DNS, '[^' .. "|" .. ']+', function(w)
			local server_dns = w
			local server_param = string.format("server %s -group %s -proxy %s", "%s", REMOTE_GROUP, proxy_server_name)

			if REMOTE_EXCLUDE == "1" then
				server_param = server_param .. " -exclude-default-group"
			end

			local isHTTPS = w:find("https://")
			if isHTTPS and isHTTPS == 1 then
				local http_host = nil
				local url = w
				local port = 443
				local s = api.split(w, ",")
				if s and #s > 1 then
					url = s[1]
					local dns_ip = s[2]
					local host_port = api.get_domain_from_url(s[1])
					if host_port and #host_port > 0 then
						http_host = host_port
						local s2 = api.split(host_port, ":")
						if s2 and #s2 > 1 then
							http_host = s2[1]
							port = s2[2]
						end 
						url = url:gsub(http_host, dns_ip)
					end
				end
				server_dns = url
				if http_host then
					server_dns = server_dns .. " -http-host " .. http_host
				end
			end
			server_param = string.format(server_param, server_dns)
			sys.exec(string.format('echo "%s" >> %s', server_param, CACHE_DNS_FILE))
		end)
	end

	local setflag= (NFTFLAG == "1") and "inet#passwall#" or ""
	local set_type= (NFTFLAG == "1") and "-nftset" or "-ipset"

	--始终用国内DNS解析节点域名
	uci:foreach(appname, "nodes", function(t)
		local address = t.address
		if address == "engage.cloudflareclient.com" then return end
		if datatypes.hostname(address) then
			set_domain_group(address, LOCAL_GROUP)
			set_domain_ipset(address, "#4:" .. setflag .. "passwall_vpslist,#6:" .. setflag .. "passwall_vpslist6")
		end
	end)
	log(string.format("  - 节点列表中的域名(vpslist)使用分组：%s", LOCAL_GROUP or "默认"))

	--屏蔽列表
	if USE_BLOCK_LIST == "1" then
		if fs.access("/usr/share/passwall/rules/block_host") then
			for line in io.lines("/usr/share/passwall/rules/block_host") do
				line = api.get_std_domain(line)
				if line ~= "" and not line:find("#") then
					set_domain_address(line, "-")
				end
			end
		end
	end

	--直连（白名单）列表
	if USE_DIRECT_LIST == "1" then
		if fs.access("/usr/share/passwall/rules/direct_host") then
			for line in io.lines("/usr/share/passwall/rules/direct_host") do
				line = api.get_std_domain(line)
				if line ~= "" and not line:find("#") then
					add_excluded_domain(line)
					set_domain_group(line, LOCAL_GROUP)
					set_domain_ipset(line, "#4:" .. setflag .. "passwall_whitelist,#6:" .. setflag .. "passwall_whitelist6")
				end
			end
			log(string.format("  - 域名白名单(whitelist)使用分组：%s", LOCAL_GROUP or "默认"))
		end
	end

	--代理（黑名单）列表
	if USE_PROXY_LIST == "1" then
		if fs.access("/usr/share/passwall/rules/proxy_host") then
			for line in io.lines("/usr/share/passwall/rules/proxy_host") do
				line = api.get_std_domain(line)
				if line ~= "" and not line:find("#") then
					add_excluded_domain(line)
					local ipset_flag = "#4:" .. setflag .. "passwall_blacklist,#6:" .. setflag .. "passwall_blacklist6"
					if NO_PROXY_IPV6 == "1" then
						set_domain_address(line, "#6")
						ipset_flag = "#4:" .. setflag .. "passwall_blacklist"
					end
					set_domain_group(line, REMOTE_GROUP)
					set_domain_ipset(line, ipset_flag)
					set_domain_extra_param(line, "-no-serve-expired")
				end
			end
			log(string.format("  - 代理域名表(blacklist)使用分组：%s", REMOTE_GROUP or "默认"))
		end
	end

	--GFW列表
	if USE_GFW_LIST == "1" then
		if fs.access("/usr/share/passwall/rules/gfwlist") then
			local domain_set_name = "passwall-gfwlist"
			local domain_file = CACHE_DNS_PATH .. "_gfwlist.list"
			sys.exec('cat /usr/share/passwall/rules/gfwlist | grep -v -E "^#" | grep -v -E "' .. excluded_domain_str .. '" > ' .. domain_file)
			sys.exec(string.format('echo "domain-set -name %s -file %s" >> %s', domain_set_name, domain_file, CACHE_DNS_FILE))
			local domain_rules_str = string.format('domain-rules /domain-set:%s/ -nameserver %s', domain_set_name, REMOTE_GROUP)
			domain_rules_str = domain_rules_str .. " -speed-check-mode none"
			domain_rules_str = domain_rules_str .. " -no-serve-expired"
			if NO_PROXY_IPV6 == "1" then
				domain_rules_str = domain_rules_str .. " -address #6"
				domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_gfwlist"
			else
				domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_gfwlist" .. ",#6:" .. setflag .. "passwall_gfwlist6"
			end
			sys.exec(string.format('echo "%s" >> %s', domain_rules_str, CACHE_DNS_FILE))
			log(string.format("  - 防火墙域名表(gfwlist)使用分组：%s", REMOTE_GROUP or "默认"))
		end
	end

	--中国列表
	if CHN_LIST ~= "0" then
		if fs.access("/usr/share/passwall/rules/chnlist") then
			local domain_set_name = "passwall-chnlist"
			local domain_file = CACHE_DNS_PATH .. "_chnlist.list"
			sys.exec('cat /usr/share/passwall/rules/chnlist | grep -v -E "^#" | grep -v -E "' .. excluded_domain_str .. '" > ' .. domain_file)
			sys.exec(string.format('echo "domain-set -name %s -file %s" >> %s', domain_set_name, domain_file, CACHE_DNS_FILE))

			if CHN_LIST == "direct" then
				local domain_rules_str = string.format('domain-rules /domain-set:%s/ %s', domain_set_name, LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "")
				domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_chnroute,#6:" .. setflag .. "passwall_chnroute6"
				sys.exec(string.format('echo "%s" >> %s', domain_rules_str, CACHE_DNS_FILE))
				log(string.format("  - 中国域名表(chnroute)使用分组：%s", LOCAL_GROUP or "默认"))
			end
			if CHN_LIST == "proxy" then
				local domain_rules_str = string.format('domain-rules /domain-set:%s/ -nameserver %s', domain_set_name, REMOTE_GROUP)
				domain_rules_str = domain_rules_str .. " -speed-check-mode none"
				domain_rules_str = domain_rules_str .. " -no-serve-expired"
				if NO_PROXY_IPV6 == "1" then
					domain_rules_str = domain_rules_str .. " -address #6"
					domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_chnroute"
				else
					domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_chnroute" .. ",#6:" .. setflag .. "passwall_chnroute6"
				end
				sys.exec(string.format('echo "%s" >> %s', domain_rules_str, CACHE_DNS_FILE))
				log(string.format("  - 中国域名表(chnroute)使用分组：%s", REMOTE_GROUP or "默认"))
			end
		end
	end

	--分流规则
	if uci:get(appname, TCP_NODE, "protocol") == "_shunt" then
		local t = uci:get_all(appname, TCP_NODE)
		local default_node_id = t["default_node"] or "_direct"
		uci:foreach(appname, "shunt_rules", function(s)
			local _node_id = t[s[".name"]] or "nil"
			if _node_id ~= "nil" and _node_id ~= "_blackhole" then
				if _node_id == "_default" then
					_node_id = default_node_id
				end

				local fwd_group = nil
				local ipset_flag = nil
				local no_ipv6 = nil

				if _node_id == "_direct" then
					fwd_group = LOCAL_GROUP
					ipset_flag = "#4:" .. setflag .. "passwall_whitelist,#6:" .. setflag .. "passwall_whitelist6"
				else
					fwd_group = REMOTE_GROUP
					ipset_flag = "#4:" .. setflag .. "passwall_shuntlist,#6:" .. setflag .. "passwall_shuntlist6"
					if NO_PROXY_IPV6 == "1" then
						ipset_flag = "#4:" .. setflag .. "passwall_shuntlist"
						no_ipv6 = true
					end
				end

				local domain_list = s.domain_list or ""
				for line in string.gmatch(domain_list, "[^\r\n]+") do
					if line ~= "" and not line:find("#") and not line:find("regexp:") and not line:find("geosite:") and not line:find("ext:") then
						if line:find("domain:") or line:find("full:") then
							line = string.match(line, ":([^:]+)$")
						end
						line = api.get_std_domain(line)
						add_excluded_domain(line)
						
						if no_ipv6 then
							set_domain_address(line, "#6")
						end
						set_domain_group(line, fwd_group)
						set_domain_ipset(line, ipset_flag)
						if fwd_group == REMOTE_GROUP then
							set_domain_extra_param(line, "-no-serve-expired")
						end
					end
				end
				if _node_id ~= "_direct" then
					log(string.format("  - Sing-Box/Xray分流规则(%s)使用分组：%s", s.remarks, fwd_group or "默认"))
				end
			end
		end)
	end

	local f_out = io.open(CACHE_DNS_FILE, "a")
	for key, value in pairs(list1) do
		local group_str = ""
		local ipset_str = ""
		local speed_check_mode_str = ""
		local address_str = ""
		local extra_param_str = ""
		if value.group and #value.group > 0 then
			group_str = group_str .. value.group
		end
		if group_str ~= "" then
			group_str = " -n " .. group_str
		end
		if value.ipsets and #value.ipsets > 0 then
			for i, ipset in ipairs(value.ipsets) do
				ipset_str = ipset_str .. ipset .. ","
			end
			ipset_str = ipset_str:sub(1, #ipset_str - 1)
		end
		if ipset_str ~= "" then
			ipset_str = " " .. set_type .. " " .. ipset_str
		end
		if value.address and #value.address > 0 then
			address_str = address_str .. value.address
		end
		if address_str ~= "" then
			address_str = " -a " .. address_str
		end
		if value.speed_check_mode and #value.speed_check_mode > 0 then
			speed_check_mode_str = value.speed_check_mode
		end
		if speed_check_mode_str ~= "" then
			speed_check_mode_str = " -c " .. speed_check_mode_str
		end
		if value.params then
			for k2, v2 in pairs(value.params) do
				extra_param_str = extra_param_str .. " " .. v2
			end
		end
		local str = string.format("domain-rules /%s/ %s%s%s%s%s\n", key, group_str, ipset_str, address_str, speed_check_mode_str, extra_param_str)
		f_out:write(str)
	end
	f_out:close()

	f_out = io.open(CACHE_TEXT_FILE, "a")
	f_out:write(new_text)
	f_out:close()
end
fs.symlink(CACHE_DNS_FILE, SMARTDNS_CONF)
sys.call(string.format('echo "conf-file %s" >> /etc/smartdns/custom.conf', string.gsub(SMARTDNS_CONF, appname, appname .. "*")))
log("  - 请让SmartDNS作为Dnsmasq的上游或重定向！")
