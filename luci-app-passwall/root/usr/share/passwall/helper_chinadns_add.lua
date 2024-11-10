local sys = require "luci.sys"
local api = require "luci.passwall.api"
local appname = "passwall"

local var = api.get_args(arg)
local FLAG = var["-FLAG"]
local LISTEN_PORT = var["-LISTEN_PORT"]
local DNS_LOCAL = var["-DNS_LOCAL"]
local DNS_TRUST = var["-DNS_TRUST"]
local USE_DIRECT_LIST = var["-USE_DIRECT_LIST"]
local USE_PROXY_LIST = var["-USE_PROXY_LIST"]
local USE_BLOCK_LIST = var["-USE_BLOCK_LIST"]
local GFWLIST = var["-GFWLIST"]
local CHNLIST = var["-CHNLIST"]
local NO_IPV6_TRUST = var["-NO_IPV6_TRUST"]
local DEFAULT_MODE = var["-DEFAULT_MODE"]
local DEFAULT_TAG = var["-DEFAULT_TAG"]
local NO_LOGIC_LOG = var["-NO_LOGIC_LOG"]
local TCP_NODE = var["-TCP_NODE"]
local NFTFLAG = var["-NFTFLAG"]

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

local function merge_array(lines1, lines2)
	for i, line in ipairs(lines2) do
		table.insert(lines1, #lines1 + 1, line)
	end
end

if not fs.access(TMP_ACL_PATH) then
	fs.mkdir(TMP_ACL_PATH, 493)
end

local setflag= (NFTFLAG == "1") and "inet@passwall@" or ""

config_lines = {
	--"verbose",
	"bind-addr 127.0.0.1",
	"bind-port " .. LISTEN_PORT,
	"china-dns " .. DNS_LOCAL,
	"trust-dns " .. DNS_TRUST,
	"filter-qtype 65"
}

--GFW列表
if GFWLIST == "1" and is_file_nonzero(RULES_PATH .. "/gfwlist") then
	tmp_lines = {
		"gfwlist-file " .. RULES_PATH .. "/gfwlist",
		"add-taggfw-ip " .. setflag .. "passwall_gfwlist," .. setflag .. "passwall_gfwlist6"
	}
	merge_array(config_lines, tmp_lines)
	if NO_IPV6_TRUST == "1" then table.insert(config_lines, "no-ipv6 tag:gfw") end
	log(string.format("  - 防火墙域名表(gfwlist)：%s", DNS_TRUST or "默认"))
end

--中国列表
if CHNLIST ~= "0" and is_file_nonzero(RULES_PATH .. "/chnlist") then
	if CHNLIST == "direct" then
		tmp_lines = {
			"chnlist-file " .. RULES_PATH .. "/chnlist",
			"ipset-name4 " .. setflag .. "passwall_chnroute",
			"ipset-name6 " .. setflag .. "passwall_chnroute6",
			"add-tagchn-ip",
			"chnlist-first"
		}
		merge_array(config_lines, tmp_lines)
		log(string.format("  - 中国域名表(chnroute)：%s", DNS_LOCAL or "默认"))
	end

	--回中国模式
	if CHNLIST == "proxy" then
		tmp_lines = {
			"group chn_proxy",
			"group-dnl " .. RULES_PATH .. "/chnlist",
			"group-upstream " .. DNS_TRUST,
			"group-ipset " .. setflag .. "passwall_chnroute," .. setflag .. "passwall_chnroute6"
		}
		merge_array(config_lines, tmp_lines)
		if NO_IPV6_TRUST == "1" then table.insert(config_lines, "no-ipv6 tag:chn_proxy") end
		log(string.format("  - 中国域名表(chnroute)：%s", DNS_TRUST or "默认"))
	end
end

--自定义规则组，后声明的组具有更高优先级
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
	tmp_lines = {
		"group directlist",
		"group-dnl " .. file_direct_host,
		"group-upstream " .. DNS_LOCAL,
		"group-ipset " .. setflag .. "passwall_whitelist," .. setflag .. "passwall_whitelist6"
	}
	merge_array(config_lines, tmp_lines)
	log(string.format("  - 域名白名单(whitelist)：%s", DNS_LOCAL or "默认"))
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
	tmp_lines = {
		"group proxylist",
		"group-dnl " .. file_proxy_host,
		"group-upstream " .. DNS_TRUST,
		"group-ipset " .. setflag .. "passwall_blacklist," .. setflag .. "passwall_blacklist6"
	}
	merge_array(config_lines, tmp_lines)
	if NO_IPV6_TRUST == "1" then table.insert(config_lines, "no-ipv6 tag:proxylist") end
	log(string.format("  - 代理域名表(blacklist)：%s", DNS_TRUST or "默认"))
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
	table.insert(config_lines, "group null")
	table.insert(config_lines, "group-dnl " .. file_block_host)
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
	tmp_lines = {
		"group vpslist",
		"group-dnl " .. file_vpslist,
		"group-upstream " .. DNS_LOCAL,
		"group-ipset " .. setflag .. "passwall_vpslist," .. setflag .. "passwall_vpslist6"
	}
	merge_array(config_lines, tmp_lines)
	log(string.format("  - 节点列表中的域名(vpslist)：%s", DNS_LOCAL or "默认"))
end

--分流规则
if uci:get(appname, TCP_NODE, "protocol") == "_shunt" then
	local white_domain, lookup_white_domain = {}, {}
	local shunt_domain, lookup_shunt_domain = {}, {}
	local blackhole_domain, lookup_blackhole_domain = {}, {}
	local file_white_host = TMP_ACL_PATH .. "/white_host"
	local file_shunt_host = TMP_ACL_PATH .. "/shunt_host"
	local file_blackhole_host = TMP_ACL_PATH .. "/blackhole_host"

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

					if _node_id == "_blackhole" then
						if line ~= "" and not line:find("#") then
							insert_unique(blackhole_domain, line, lookup_blackhole_domain)
						end
					elseif _node_id == "_direct" then
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
				log(string.format("  - Sing-Box/Xray分流规则(%s)：%s", s.remarks, DNS_TRUST or "默认"))
			end
		end
	end)

	if is_file_nonzero(file_blackhole_host) == nil then
		if #blackhole_domain > 0 then
			local f_out = io.open(file_blackhole_host, "w")
			for i = 1, #blackhole_domain do
				f_out:write(blackhole_domain[i] .. "\n")
			end
			f_out:close()
		end
	end

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

	if is_file_nonzero(file_blackhole_host) then
		for i, v in ipairs(config_lines) do   --添加到屏蔽组一同处理
			if v == "group-dnl " .. file_block_host then
				config_lines[i] = "group-dnl " .. file_block_host .. "," .. file_blackhole_host
				break
			end
		end
	end

	if is_file_nonzero(file_white_host) then
		for i, v in ipairs(config_lines) do   --添加到白名单组一同处理
			if v == "group-dnl " .. file_direct_host then
				config_lines[i] = "group-dnl " .. file_direct_host .. "," .. file_white_host
				break
			end
		end
	end

	if is_file_nonzero(file_shunt_host) then
		tmp_lines = {
			"group shuntlist",
			"group-dnl " .. file_shunt_host,
			"group-upstream " .. DNS_TRUST,
			"group-ipset " .. setflag .. "passwall_shuntlist," .. setflag .. "passwall_shuntlist6"
		}
		if NO_IPV6_TRUST == "1" then table.insert(tmp_lines, "no-ipv6 tag:shuntlist") end
		-- 在 "filter-qtype 65" 后插入 tmp_lines （shuntlist优先级最低）
		for i, line in ipairs(config_lines) do
			if line == "filter-qtype 65" then
				for j, tmp_line in ipairs(tmp_lines) do
					table.insert(config_lines, i + j, tmp_line)
				end
				break
			end
		end
	end

end

--只使用gfwlist模式，GFW列表以外的域名及默认使用本地DNS
if GFWLIST == "1" and CHNLIST == "0" then DEFAULT_TAG = "chn" end

--回中国模式，中国列表以外的域名及默认使用本地DNS
if CHNLIST == "proxy" then DEFAULT_TAG = "chn" end

--全局模式，默认使用远程DNS
if DEFAULT_MODE == "proxy" and CHNLIST == "0" and GFWLIST == "0" then
	DEFAULT_TAG = "gfw"
	if NO_IPV6_TRUST == "1" then table.insert(config_lines, "no-ipv6") end
end

--是否接受直连 DNS 空响应
if DEFAULT_TAG == "none_noip" then table.insert(config_lines, "noip-as-chnip") end

if DEFAULT_TAG == nil or DEFAULT_TAG == "smart" or DEFAULT_TAG == "none_noip" then DEFAULT_TAG = "none" end

table.insert(config_lines, "default-tag " .. DEFAULT_TAG)
table.insert(config_lines, "cache 4096")
table.insert(config_lines, "cache-stale 3600")

if DEFAULT_TAG == "none" then
	table.insert(config_lines, "verdict-cache 5000")
end

table.insert(config_lines, "hosts")

if DEFAULT_TAG == "chn" then
	log(string.format("  - 默认：%s", DNS_LOCAL))
elseif  DEFAULT_TAG == "gfw" then
	log(string.format("  - 默认：%s", DNS_TRUST))
else
	log(string.format("  - 默认：%s", "127.0.0.1#" .. LISTEN_PORT))
end

--输出配置文件
if #config_lines > 0 then
	for i = 1, #config_lines do
		print(config_lines[i])
	end
end

log("  - ChinaDNS-NG已作为Dnsmasq上游，如果你自行配置了错误的DNS流程，将会导致域名(直连/代理域名)分流失效！！！")
