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
local GFWLIST = var["-GFWLIST"]
local CHNLIST = var["-CHNLIST"]
local NO_IPV6_TRUST = var["-NO_IPV6_TRUST"]
local DEFAULT_MODE = var["-DEFAULT_MODE"]
local DEFAULT_TAG = var["-DEFAULT_TAG"]
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

local function is_file_nonzero(path)
	if path and #path > 1 then
		if sys.exec('[ -s "%s" ] && echo -n 1' % path) == "1" then
			return true
		end
	end
	return nil
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

--始终用国内DNS解析节点域名
local file_vpslist = TMP_ACL_PATH .. "/vpslist"
if not is_file_nonzero(file_vpslist) then
	local vpslist_out = io.open(file_vpslist, "w")
	uci:foreach(appname, "nodes", function(t)
		local address = t.address
		if address == "engage.cloudflareclient.com" then return end
		if datatypes.hostname(address) then
			vpslist_out:write(address .. "\n")
		end
	end)
	vpslist_out:close()
end
if is_file_nonzero(file_vpslist) then
	tmp_lines = {
		"group vpslist",
		"group-dnl " .. file_vpslist,
		"group-upstream " .. DNS_LOCAL,
		"group-ipset " .. setflag .. "passwall_vpslist," .. setflag .. "passwall_vpslist6"
	}
	merge_array(config_lines, tmp_lines)
end

--直连（白名单）列表
local file_direct_host = TMP_ACL_PATH .. "/direct_host"
if USE_DIRECT_LIST == "1" and not fs.access(file_direct_host) then   --对自定义列表进行清洗
	local direct_domain = {}
	for line in io.lines(RULES_PATH .. "/direct_host") do
		line = api.get_std_domain(line)
		if line ~= "" and not line:find("#") then
			table.insert(direct_domain, line)
		end
	end
	if #direct_domain > 0 then
		local direct_out = io.open(file_direct_host, "w")
		for i = 1, #direct_domain do
			direct_out:write(direct_domain[i] .. "\n")
		end
		direct_out:close()
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
end

--代理（黑名单）列表
local file_proxy_host = TMP_ACL_PATH .. "/proxy_host"
if USE_PROXY_LIST == "1" and not fs.access(file_proxy_host) then   --对自定义列表进行清洗
	local proxy_domain = {}
	for line in io.lines(RULES_PATH .. "/proxy_host") do
		line = api.get_std_domain(line)
		if line ~= "" and not line:find("#") then
			table.insert(proxy_domain, line)
		end
	end
	if #proxy_domain > 0 then
		local proxy_out = io.open(file_proxy_host, "w")
		for i = 1, #proxy_domain do
			proxy_out:write(proxy_domain[i] .. "\n")
		end
		proxy_out:close()
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
end

--GFW列表
if GFWLIST == "1" and is_file_nonzero(RULES_PATH .. "/gfwlist") then
	tmp_lines = {
		"gfwlist-file " .. RULES_PATH .. "/gfwlist",
		"add-taggfw-ip " .. setflag .. "passwall_gfwlist," .. setflag .. "passwall_gfwlist6"
	}
	merge_array(config_lines, tmp_lines)
	if NO_IPV6_TRUST == "1" then table.insert(config_lines, "no-ipv6 tag:gfw") end
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

--输出配置文件
if #config_lines > 0 then
	for i = 1, #config_lines do
		print(config_lines[i])
	end
end
