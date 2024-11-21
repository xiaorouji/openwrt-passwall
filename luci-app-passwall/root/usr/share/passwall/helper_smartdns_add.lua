require "luci.sys"
local api = require "luci.passwall.api"
local appname = "passwall"

local var = api.get_args(arg)
local FLAG = var["-FLAG"]
local SMARTDNS_CONF = var["-SMARTDNS_CONF"]
local LOCAL_GROUP = var["-LOCAL_GROUP"]
local REMOTE_GROUP = var["-REMOTE_GROUP"]
local REMOTE_PROXY_SERVER = var["-REMOTE_PROXY_SERVER"]
local USE_DEFAULT_DNS = var["-USE_DEFAULT_DNS"]
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

local uci = api.uci
local sys = api.sys
local fs = api.fs
local datatypes = api.datatypes

local TMP_PATH = "/tmp/etc/" .. appname
local TMP_ACL_PATH = TMP_PATH .. "/acl"
local RULES_PATH = "/usr/share/" .. appname .. "/rules"
local config_lines = {}
local tmp_lines = {}

local function log(...)
	if NO_LOGIC_LOG == "1" then
		return
	end
	api.log(...)
end

local function is_file_nonzero(path)
	if path and #path > 1 then
		if sys.exec('[ -s "%s" ] && echo -n 1' % path) == "1" then
			return true
		end
	end
	return nil
end

local function insert_unique(dest_table, value, lookup_table)
	if not lookup_table[value] then
		table.insert(dest_table, value)
		lookup_table[value] = true
	end
end

local function merge_array(array1, array2)
	for i, line in ipairs(array2) do
		table.insert(array1, #array1 + 1, line)
	end
end

local function insert_array_before(array1, array2, target) --将array2插入到array1的target前面，target不存在则追加
	for i, line in ipairs(array1) do
		if line == target then
			for j = #array2, 1, -1 do
				table.insert(array1, i, array2[j])
			end
			return
		end
	end
	merge_array(array1, array2)
end

local function insert_array_after(array1, array2, target) --将array2插入到array1的target后面，target不存在则追加
	for i, line in ipairs(array1) do
		if line == target then
			for j = 1, #array2 do
				table.insert(array1, i + j, array2[j])
			end
			return
		end
	end
	merge_array(array1, array2)
end

if not fs.access(TMP_ACL_PATH) then
	fs.mkdir(TMP_ACL_PATH)
end

if not fs.access(CACHE_PATH) then
	fs.mkdir(CACHE_PATH)
end

if LOCAL_GROUP == "nil" then
	LOCAL_GROUP = nil
	log("  * 注意：国内分组名未设置，可能会导致 DNS 解析异常！")
end

if not REMOTE_GROUP or REMOTE_GROUP == "nil" then
	REMOTE_GROUP = "passwall_proxy"
	if TUN_DNS then
		TUN_DNS = TUN_DNS:gsub("#", ":")
	end
	sys.call('sed -i "/passwall/d" /etc/smartdns/custom.conf >/dev/null 2>&1')
end

local proxy_server_name = "passwall-proxy-server"
config_lines = {
	"force-qtype-SOA 65",
	"server 114.114.114.114 -bootstrap-dns",
	string.format("proxy-server socks5://%s -name %s", REMOTE_PROXY_SERVER, proxy_server_name)
}
if true then
	string.gsub(TUN_DNS, '[^' .. "|" .. ']+', function(w)
		local server_dns = w
		local server_param = string.format("server %s -group %s -proxy %s", "%s", REMOTE_GROUP, proxy_server_name)

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
		table.insert(config_lines, server_param)
	end)
end

--设置默认 DNS 分组(托底组)
local DEFAULT_DNS_GROUP = (USE_DEFAULT_DNS == "direct" and LOCAL_GROUP) or 
                          (USE_DEFAULT_DNS == "remote" and REMOTE_GROUP)
local only_global = (DEFAULT_PROXY_MODE == "proxy" and CHN_LIST == "0" and USE_GFW_LIST == "0") and 1 --没有启用中国列表和GFW列表时(全局)
if only_global == 1 then
	DEFAULT_DNS_GROUP = REMOTE_GROUP
end
if DEFAULT_DNS_GROUP then
	local domain_rules_str = "domain-rules /./ -nameserver " .. DEFAULT_DNS_GROUP
	if DEFAULT_DNS_GROUP == REMOTE_GROUP then
		domain_rules_str = domain_rules_str .. " -speed-check-mode none -d no -no-serve-expired"
		if NO_PROXY_IPV6 == "1" and only_global == 1 and uci:get(appname, TCP_NODE, "protocol") ~= "_shunt" then
			domain_rules_str = domain_rules_str .. " -address #6"
		end
	end
	table.insert(config_lines, domain_rules_str)
end

local setflag = (NFTFLAG == "1") and "inet#passwall#" or ""
local set_type = (NFTFLAG == "1") and "-nftset" or "-ipset"

--预设排序标签(越往后优先级越高)
for i = 1, 8 do
	table.insert(config_lines, "#--" .. i)
end

--屏蔽列表
local file_block_host = TMP_ACL_PATH .. "/block_host"
if USE_BLOCK_LIST == "1" and not fs.access(file_block_host) then   --对自定义列表进行清洗
	local block_domain, lookup_block_domain = {}, {}
	for line in io.lines(RULES_PATH .. "/block_host") do
		line = api.get_std_domain(line)
		if line ~= "" and not line:find("#") then
			insert_unique(block_domain, line, lookup_block_domain)
		end
	end
	if #block_domain > 0 then
		local f_out = io.open(file_block_host, "w")
		for i = 1, #block_domain do
			f_out:write(block_domain[i] .. "\n")
		end
		f_out:close()
	end
end
if USE_BLOCK_LIST == "1" and is_file_nonzero(file_block_host) then
	local domain_set_name = "passwall-block"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, file_block_host),
		string.format("domain-rules /domain-set:%s/ -a #", domain_set_name)
	}
	insert_array_after(config_lines, tmp_lines, "#--7")
end

--始终用国内DNS解析节点域名
local file_vpslist = TMP_ACL_PATH .. "/vpslist"
if not is_file_nonzero(file_vpslist) then
	local f_out = io.open(file_vpslist, "w")
	uci:foreach(appname, "nodes", function(t)
		local address = t.address
		if address == "engage.cloudflareclient.com" then return end
		if datatypes.hostname(address) then
			f_out:write(address .. "\n")
		end
	end)
	f_out:close()
end
if is_file_nonzero(file_vpslist) then
	local domain_set_name = "passwall-vpslist"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, file_vpslist)
	}
	local domain_rules_str = string.format('domain-rules /domain-set:%s/ %s', domain_set_name, LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "")
	domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_vpslist,#6:" .. setflag .. "passwall_vpslist6"
	table.insert(tmp_lines, domain_rules_str)
	insert_array_after(config_lines, tmp_lines, "#--8")
	log(string.format("  - 节点列表中的域名(vpslist)使用分组：%s", LOCAL_GROUP or "默认"))
end

--直连（白名单）列表
local file_direct_host = TMP_ACL_PATH .. "/direct_host"
if USE_DIRECT_LIST == "1" and not fs.access(file_direct_host) then   --对自定义列表进行清洗
	local direct_domain, lookup_direct_domain = {}, {}
	for line in io.lines(RULES_PATH .. "/direct_host") do
		line = api.get_std_domain(line)
		if line ~= "" and not line:find("#") then
			insert_unique(direct_domain, line, lookup_direct_domain)
		end
	end
	if #direct_domain > 0 then
		local f_out = io.open(file_direct_host, "w")
		for i = 1, #direct_domain do
			f_out:write(direct_domain[i] .. "\n")
		end
		f_out:close()
	end
end
if USE_DIRECT_LIST == "1" and is_file_nonzero(file_direct_host) then
	local domain_set_name = "passwall-directlist"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, file_direct_host)
	}
	local domain_rules_str = string.format('domain-rules /domain-set:%s/ %s', domain_set_name, LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "")
	domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_whitelist,#6:" .. setflag .. "passwall_whitelist6"
	table.insert(tmp_lines, domain_rules_str)
	insert_array_after(config_lines, tmp_lines, "#--6")
	log(string.format("  - 域名白名单(whitelist)使用分组：%s", LOCAL_GROUP or "默认"))
end

--代理（黑名单）列表
local file_proxy_host = TMP_ACL_PATH .. "/proxy_host"
if USE_PROXY_LIST == "1" and not fs.access(file_proxy_host) then   --对自定义列表进行清洗
	local proxy_domain, lookup_proxy_domain = {}, {}
	for line in io.lines(RULES_PATH .. "/proxy_host") do
		line = api.get_std_domain(line)
		if line ~= "" and not line:find("#") then
			insert_unique(proxy_domain, line, lookup_proxy_domain)
		end
	end
	if #proxy_domain > 0 then
		local f_out = io.open(file_proxy_host, "w")
		for i = 1, #proxy_domain do
			f_out:write(proxy_domain[i] .. "\n")
		end
		f_out:close()
	end
end
if USE_PROXY_LIST == "1" and is_file_nonzero(file_proxy_host) then
	local domain_set_name = "passwall-proxylist"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, file_proxy_host)
	}
	local domain_rules_str = string.format('domain-rules /domain-set:%s/ -nameserver %s', domain_set_name, REMOTE_GROUP)
	domain_rules_str = domain_rules_str .. " -speed-check-mode none"
	domain_rules_str = domain_rules_str .. " -no-serve-expired"
	if NO_PROXY_IPV6 == "1" then
		domain_rules_str = domain_rules_str .. " -address #6"
		domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_blacklist"
	else
		domain_rules_str = domain_rules_str .. " -d no " .. set_type .. " #4:" .. setflag .. "passwall_blacklist" .. ",#6:" .. setflag .. "passwall_blacklist6"
	end
	table.insert(tmp_lines, domain_rules_str)
	insert_array_after(config_lines, tmp_lines, "#--5")
	log(string.format("  - 代理域名表(blacklist)使用分组：%s", REMOTE_GROUP or "默认"))
end

--GFW列表
if USE_GFW_LIST == "1" and is_file_nonzero(RULES_PATH .. "/gfwlist") then
	local domain_set_name = "passwall-gfwlist"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, RULES_PATH .. "/gfwlist")
	}
	local domain_rules_str = string.format('domain-rules /domain-set:%s/ -nameserver %s', domain_set_name, REMOTE_GROUP)
	domain_rules_str = domain_rules_str .. " -speed-check-mode none"
	domain_rules_str = domain_rules_str .. " -no-serve-expired"
	if NO_PROXY_IPV6 == "1" then
		domain_rules_str = domain_rules_str .. " -address #6"
		domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_gfwlist"
	else
		domain_rules_str = domain_rules_str .. " -d no " .. set_type .. " #4:" .. setflag .. "passwall_gfwlist" .. ",#6:" .. setflag .. "passwall_gfwlist6"
	end
	table.insert(tmp_lines, domain_rules_str)
	insert_array_after(config_lines, tmp_lines, "#--1")
	log(string.format("  - 防火墙域名表(gfwlist)使用分组：%s", REMOTE_GROUP or "默认"))
end

--中国列表
if CHN_LIST ~= "0" and is_file_nonzero(RULES_PATH .. "/chnlist") then
	local domain_set_name = "passwall-chnlist"
	tmp_lines = {
		string.format("domain-set -name %s -file %s", domain_set_name, RULES_PATH .. "/chnlist")
	}

	if CHN_LIST == "direct" then
		local domain_rules_str = string.format('domain-rules /domain-set:%s/ %s', domain_set_name, LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "")
		domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_chnroute,#6:" .. setflag .. "passwall_chnroute6"
		table.insert(tmp_lines, domain_rules_str)
		insert_array_after(config_lines, tmp_lines, "#--2")
		log(string.format("  - 中国域名表(chnroute)使用分组：%s", LOCAL_GROUP or "默认"))
	end

	--回中国模式
	if CHN_LIST == "proxy" then
		local domain_rules_str = string.format('domain-rules /domain-set:%s/ -nameserver %s', domain_set_name, REMOTE_GROUP)
		domain_rules_str = domain_rules_str .. " -speed-check-mode none"
		domain_rules_str = domain_rules_str .. " -no-serve-expired"
		if NO_PROXY_IPV6 == "1" then
			domain_rules_str = domain_rules_str .. " -address #6"
			domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_chnroute"
		else
			domain_rules_str = domain_rules_str .. " -d no " .. set_type .. " #4:" .. setflag .. "passwall_chnroute" .. ",#6:" .. setflag .. "passwall_chnroute6"
		end
		table.insert(tmp_lines, domain_rules_str)
		insert_array_after(config_lines, tmp_lines, "#--2")
		log(string.format("  - 中国域名表(chnroute)使用分组：%s", REMOTE_GROUP or "默认"))
	end
end

--分流规则
if uci:get(appname, TCP_NODE, "protocol") == "_shunt" then
	local white_domain, lookup_white_domain = {}, {}
	local shunt_domain, lookup_shunt_domain = {}, {}
	local file_white_host = TMP_ACL_PATH .. "/white_host"
	local file_shunt_host = TMP_ACL_PATH .. "/shunt_host"

	local t = uci:get_all(appname, TCP_NODE)
	local default_node_id = t["default_node"] or "_direct"
	uci:foreach(appname, "shunt_rules", function(s)
		local _node_id = t[s[".name"]] or "nil"
		if _node_id ~= "nil" and _node_id ~= "_blackhole" then
			if _node_id == "_default" then
				_node_id = default_node_id
			end

			local domain_list = s.domain_list or ""
			for line in string.gmatch(domain_list, "[^\r\n]+") do
				if line ~= "" and not line:find("#") and not line:find("regexp:") and not line:find("geosite:") and not line:find("ext:") then
					if line:find("domain:") or line:find("full:") then
						line = string.match(line, ":([^:]+)$")
					end
					line = api.get_std_domain(line)

					if _node_id == "_direct" then
						if line ~= "" and not line:find("#") then
							insert_unique(white_domain, line, lookup_white_domain)
						end
					else
						if line ~= "" and not line:find("#") then
							insert_unique(shunt_domain, line, lookup_shunt_domain)
						end
					end
				end
			end

			if _node_id ~= "_direct" then
				log(string.format("  - Sing-Box/Xray分流规则(%s)使用分组：%s", s.remarks, REMOTE_GROUP or "默认"))
			end
		end
	end)

	if is_file_nonzero(file_white_host) == nil then
		if #white_domain > 0 then
			local f_out = io.open(file_white_host, "w")
			for i = 1, #white_domain do
				f_out:write(white_domain[i] .. "\n")
			end
			f_out:close()
		end
	end

	if is_file_nonzero(file_shunt_host) == nil then
		if #shunt_domain > 0 then
			local f_out = io.open(file_shunt_host, "w")
			for i = 1, #shunt_domain do
				f_out:write(shunt_domain[i] .. "\n")
			end
			f_out:close()
		end
	end

	if is_file_nonzero(file_white_host) then
		local domain_set_name = "passwall-whitehost"
		tmp_lines = {
			string.format("domain-set -name %s -file %s", domain_set_name, file_white_host)
		}
		local domain_rules_str = string.format('domain-rules /domain-set:%s/ %s', domain_set_name, LOCAL_GROUP and "-nameserver " .. LOCAL_GROUP or "")
		domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_whitelist,#6:" .. setflag .. "passwall_whitelist6"
		table.insert(tmp_lines, domain_rules_str)
		insert_array_after(config_lines, tmp_lines, "#--3")
	end

	if is_file_nonzero(file_shunt_host) then
		local domain_set_name = "passwall-shuntlist"
		tmp_lines = {
			string.format("domain-set -name %s -file %s", domain_set_name, file_shunt_host)
		}
		local domain_rules_str = string.format('domain-rules /domain-set:%s/ -nameserver %s', domain_set_name, REMOTE_GROUP)
		domain_rules_str = domain_rules_str .. " -speed-check-mode none"
		domain_rules_str = domain_rules_str .. " -no-serve-expired"
		if NO_PROXY_IPV6 == "1" then
			domain_rules_str = domain_rules_str .. " -address #6"
			domain_rules_str = domain_rules_str .. " " .. set_type .. " #4:" .. setflag .. "passwall_shuntlist"
		else
			domain_rules_str = domain_rules_str .. " -d no " .. set_type .. " #4:" .. setflag .. "passwall_shuntlist" .. ",#6:" .. setflag .. "passwall_shuntlist6"
		end
		table.insert(tmp_lines, domain_rules_str)
		insert_array_after(config_lines, tmp_lines, "#--4")
	end

end

if #config_lines > 0 then
	local f_out = io.open(CACHE_DNS_FILE, "w")
	for i = 1, #config_lines do
		line = config_lines[i]
		if line ~= "" and not line:find("^#--") then
			f_out:write(line .. "\n")
		end
	end
	f_out:close()
end

if DEFAULT_DNS_GROUP then
	log(string.format("  - 默认分组：%s", DEFAULT_DNS_GROUP))
end

fs.symlink(CACHE_DNS_FILE, SMARTDNS_CONF)
sys.call(string.format('echo "conf-file %s" >> /etc/smartdns/custom.conf', string.gsub(SMARTDNS_CONF, appname, appname .. "*")))
log("  - 请让SmartDNS作为Dnsmasq的上游或重定向！")
