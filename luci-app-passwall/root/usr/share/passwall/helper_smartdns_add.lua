require "luci.sys"
local api = require "luci.model.cbi.passwall.api.api"

local var = api.get_args(arg)
local FLAG = var["-FLAG"]
local SMARTDNS_CONF = var["-SMARTDNS_CONF"]
local LOCAL_GROUP = var["-LOCAL_GROUP"]
local REMOTE_GROUP = var["-REMOTE_GROUP"]
local REMOTE_FAKEDNS = var["-REMOTE_FAKEDNS"]
local TUN_DNS = var["-TUN_DNS"]
local TCP_NODE = var["-TCP_NODE"]
local PROXY_MODE = var["-PROXY_MODE"]
local NO_PROXY_IPV6 = var["-NO_PROXY_IPV6"]
local NO_LOGIC_LOG = var["-NO_LOGIC_LOG"]
local NFTFLAG = var["-NFTFLAG"]
local LOG_FILE = api.LOG_FILE
local CACHE_PATH = api.CACHE_PATH
local CACHE_FLAG = "dns_" .. FLAG
local CACHE_DNS_PATH = CACHE_PATH .. "/" .. CACHE_FLAG
local CACHE_DNS_FILE = CACHE_DNS_PATH .. ".conf"
local CACHE_TEXT_FILE = CACHE_DNS_PATH .. ".txt"
local SMARTDNS_PATH = "/tmp/etc/smartdns"

local uci = api.uci
local sys = api.sys
local jsonc = api.jsonc
local appname = api.appname
local fs = api.fs
local datatypes = api.datatypes

local list1 = {}
local excluded_domain = {}
local excluded_domain_str = "!"

local function log(...)
    if NO_LOGIC_LOG == "1" then
        return
    end
	local f, err = io.open(LOG_FILE, "a")
    if f and err == nil then
        local str = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
        f:write(str .. "\n")
        f:close()
    end
end

--从url获取域名
local function get_domain_from_url(url)
    if url then
        if datatypes.hostname(url) then
            return url
        end
        local domain = url:match("//([^/]+)")
        if domain then
            return domain
        end
    end
    return ""
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

local function set_domain_address(domain, address)
    if domain == "" or domain:find("#") then
        return
    end
    if not list1[domain] then
        list1[domain] = {
            ipsets = {}
        }
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
        list1[domain] = {
            ipsets = {}
        }
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
        list1[domain] = {
            ipsets = {}
        }
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
local subscribe_proxy=uci:get(appname, "@global_subscribe[0]", "subscribe_proxy") or "0"
local new_rules = luci.sys.exec("echo -n $(find /usr/share/passwall/rules -type f | xargs md5sum)")
local new_text = SMARTDNS_CONF .. LOCAL_GROUP .. REMOTE_GROUP .. REMOTE_FAKEDNS .. TUN_DNS .. PROXY_MODE .. NO_PROXY_IPV6 .. subscribe_proxy .. new_rules
if fs.access(CACHE_TEXT_FILE) then
    for line in io.lines(CACHE_TEXT_FILE) do
        cache_text = line
    end
end

if cache_text ~= new_text then
    api.remove(CACHE_DNS_PATH .. "*")
end

local global = PROXY_MODE:find("global")
local returnhome = PROXY_MODE:find("returnhome")
local chnlist = PROXY_MODE:find("chnroute")
local gfwlist = PROXY_MODE:find("gfwlist")

if not REMOTE_GROUP or REMOTE_GROUP == "nil" then
    REMOTE_GROUP = "passwall_proxy"
    if TUN_DNS then
        TUN_DNS = TUN_DNS:gsub("#", ":")
    end
    sys.call('sed -i "/passwall/d" /etc/smartdns/custom.conf >/dev/null 2>&1')
end

local setflag= (NFTFLAG == "1") and "inet#fw4#" or ""

if not fs.access(CACHE_DNS_FILE) then
    sys.call(string.format('echo "server %s  -group %s -exclude-default-group" >> %s', TUN_DNS, REMOTE_GROUP, CACHE_DNS_FILE))
    --屏蔽列表
    for line in io.lines("/usr/share/passwall/rules/block_host") do
        if line ~= "" and not line:find("#") then
            set_domain_address(line, "-")
        end
    end

    --始终用国内DNS解析节点域名
    uci:foreach(appname, "nodes", function(t)
        local address = t.address
        if datatypes.hostname(address) then
            set_domain_group(address, LOCAL_GROUP)
            set_domain_ipset(address, "#4:" .. setflag .. "vpsiplist,#6:" .. setflag .. "vpsiplist6")
        end
    end)
    log(string.format("  - 节点列表中的域名(vpsiplist)使用分组：%s", LOCAL_GROUP or "默认"))

    --始终用国内DNS解析直连（白名单）列表
    for line in io.lines("/usr/share/passwall/rules/direct_host") do
        if line ~= "" and not line:find("#") then
            add_excluded_domain(line)
            set_domain_group(line, LOCAL_GROUP)
            set_domain_ipset(line, "#4:" .. setflag .. "whitelist,#6:" .. setflag .. "whitelist6")
        end
    end
    log(string.format("  - 域名白名单(whitelist)使用分组：%s", LOCAL_GROUP or "默认"))

    local fwd_group = LOCAL_GROUP
    local ipset_flag = "#4:" .. setflag .. "whitelist,#6:" .. setflag .. "whitelist6"
    local no_ipv6
    if subscribe_proxy == "1" then
        fwd_group = REMOTE_GROUP
        ipset_flag = "#4:" .. setflag .. "blacklist,#6:" .. setflag .. "blacklist6"
        if NO_PROXY_IPV6 == "1" then
            ipset_flag = "#4:" .. setflag .. "blacklist"
            no_ipv6 = true
        end
        if REMOTE_FAKEDNS == "1" then
            ipset_flag = nil
        end
    end
    uci:foreach(appname, "subscribe_list", function(t)
        local domain = get_domain_from_url(t.url)
        if domain then
            if no_ipv6 then
                set_domain_address(domain, "#6")
            end
            set_domain_group(domain, fwd_group)
            set_domain_ipset(domain, ipset_flag)
        end
    end)
    log(string.format("  - 节点订阅域名(blacklist)使用分组：%s", fwd_group or "默认"))

    --始终使用远程DNS解析代理（黑名单）列表
    for line in io.lines("/usr/share/passwall/rules/proxy_host") do
        if line ~= "" and not line:find("#") then
            add_excluded_domain(line)
            local ipset_flag = "#4:" .. setflag .. "blacklist,#6:" .. setflag .. "blacklist6"
            if NO_PROXY_IPV6 == "1" then
                set_domain_address(line, "#6")
                ipset_flag = "#4:" .. setflag .. "blacklist"
            end
            if REMOTE_FAKEDNS == "1" then
                ipset_flag = nil
            end
            set_domain_group(line, REMOTE_GROUP)
            set_domain_ipset(line, ipset_flag)
        end
    end
    log(string.format("  - 代理域名表(blacklist)使用分组：%s", REMOTE_GROUP or "默认"))

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

                fwd_group = nil
                ipset_flag = nil
                no_ipv6 = nil

                if _node_id == "_direct" then
                    fwd_group = LOCAL_GROUP
                    ipset_flag = "#4:" .. setflag .. "whitelist,#6:" .. setflag .. "whitelist6"
                else
                    fwd_group = REMOTE_GROUP
                    ipset_flag = "#4:" .. setflag .. "shuntlist,#6:" .. setflag .. "shuntlist6"
                    if NO_PROXY_IPV6 == "1" then
                        ipset_flag = "#4:" .. setflag .. "shuntlist"
                        no_ipv6 = true
                    end
                    if REMOTE_FAKEDNS == "1" then
                        ipset_flag = nil
                    end
                end

                local domain_list = s.domain_list or ""
                for line in string.gmatch(domain_list, "[^\r\n]+") do
                    if line ~= "" and not line:find("#") and not line:find("regexp:") and not line:find("geosite:") and not line:find("ext:") then
                        if line:find("domain:") or line:find("full:") then
                            line = string.match(line, ":([^:]+)$")
                        end
                        add_excluded_domain(line)
                        
                        if no_ipv6 then
                            set_domain_address(line, "#6")
                        end
                        set_domain_group(line, fwd_group)
                        set_domain_ipset(line, ipset_flag)
                    end
                end
                if _node_id ~= "_direct" then
                    log(string.format("  - V2ray/Xray分流规则(%s)使用分组：%s", s.remarks, fwd_group or "默认"))
                end
            end
        end)
    end

    --如果没有使用回国模式
    if not returnhome then
        if fs.access("/usr/share/passwall/rules/gfwlist") then
            local gfwlist_str = sys.exec('cat /usr/share/passwall/rules/gfwlist | grep -v -E "^#" | grep -v -E "' .. excluded_domain_str .. '"')
            for line in string.gmatch(gfwlist_str, "[^\r\n]+") do
                if line ~= "" then
                    local ipset_flag = "#4:" .. setflag .. "gfwlist,#6:" .. setflag .. "gfwlist6"
                    if NO_PROXY_IPV6 == "1" then
                        ipset_flag = "#4:" .. setflag .. "gfwlist"
                        set_domain_address(line, "#6")
                    end
                    fwd_group = REMOTE_GROUP
                    if REMOTE_FAKEDNS == "1" then
                        ipset_flag = nil
                    end
                    set_domain_group(line, fwd_group)
                    set_domain_ipset(line, ipset_flag)
                end
            end
            log(string.format("  - 防火墙域名表(gfwlist)使用分组：%s", fwd_group or "默认"))
        end

        if fs.access("/usr/share/passwall/rules/chnlist") and chnlist then
            local chnlist_str = sys.exec('cat /usr/share/passwall/rules/chnlist | grep -v -E "^#" | grep -v -E "' .. excluded_domain_str .. '"')
            for line in string.gmatch(chnlist_str, "[^\r\n]+") do
                if line ~= "" then
                    set_domain_group(line, LOCAL_GROUP)
                    set_domain_ipset(line, "#4:" .. setflag .. "chnroute,#6:" .. setflag .. "chnroute6")
                end
            end
        end
        log(string.format("  - 中国域名表(chnroute)使用分组：%s", LOCAL_GROUP or "默认"))
    else
        if fs.access("/usr/share/passwall/rules/chnlist") then
            local chnlist_str = sys.exec('cat /usr/share/passwall/rules/chnlist | grep -v -E "^#" | grep -v -E "' .. excluded_domain_str .. '"')
            for line in string.gmatch(chnlist_str, "[^\r\n]+") do
                if line ~= "" then
                    local ipset_flag = "#4:" .. setflag .. "chnroute,#6:" .. setflag .. "chnroute6"
                    if NO_PROXY_IPV6 == "1" then
                        ipset_flag = "#4:" .. setflag .. "chnroute"
                        set_domain_address(line, "#6")
                    end
                    set_domain_group(line, REMOTE_GROUP)
                    if REMOTE_FAKEDNS == "1" then
                        ipset_flag = nil
                    end
                    set_domain_ipset(line, ipset_flag)
                end
            end
            log(string.format("  - 中国域名表(chnroute)使用分组：%s", REMOTE_GROUP or "默认"))
        end
    end

    local f_out = io.open(CACHE_DNS_FILE, "a")
    for key, value in pairs(list1) do
        local group_str = ""
        local ipset_str = ""
        local speed_check_mode_str = ""
        local address_str = ""
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
            ipset_str = " -p " .. ipset_str
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
        local str = string.format("domain-rules /%s/ %s%s%s%s\n", key, group_str, ipset_str, address_str, speed_check_mode_str)
        f_out:write(str)
    end
    f_out:close()

    f_out = io.open(CACHE_TEXT_FILE, "a")
    f_out:write(new_text)
    f_out:close()
end
fs.symlink(CACHE_DNS_FILE, SMARTDNS_CONF)
sys.call(string.format('echo "conf-file %s" >> /etc/smartdns/custom.conf', SMARTDNS_CONF))
log("  - 请让SmartDNS作为Dnsmasq的上游或重定向！")
