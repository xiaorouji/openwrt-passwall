#!/usr/bin/lua

local api = require ("luci.passwall.api")
local name = api.appname
local uci = api.uci
local sys = api.sys
local jsonc = api.jsonc
local fs = api.fs

local arg1 = arg[1]
local arg2 = arg[2]
local arg3 = arg[3]

local nftable_name = "inet passwall"
local rule_path = "/usr/share/" .. name .. "/rules"
local reboot = 0
local gfwlist_update = "0"
local chnroute_update = "0"
local chnroute6_update = "0"
local chnlist_update = "0"
local geoip_update = "0"
local geosite_update = "0"

-- match comments/title/whitelist/ip address/excluded_domain
local comment_pattern = "^[#!\\[@]+"
local ip_pattern = "^%d+%.%d+%.%d+%.%d+"
local ip4_ipset_pattern = "^%d+%.%d+%.%d+%.%d+[%/][%d]+$"
local ip6_ipset_pattern = ":-[%x]+%:+[%x]-[%/][%d]+$"
local domain_pattern = "([%w%-]+%.[%w%.%-]+)[%/%*]*"
local excluded_domain = {"apple.com","sina.cn","sina.com.cn","baidu.com","byr.cn","jlike.com","weibo.com","zhongsou.com","youdao.com","sogou.com","so.com","soso.com","aliyun.com","taobao.com","jd.com","qq.com","bing.com"}

local gfwlist_url = uci:get(name, "@global_rules[0]", "gfwlist_url") or {"https://fastly.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt"}
local chnroute_url = uci:get(name, "@global_rules[0]", "chnroute_url") or {"https://ispip.clang.cn/all_cn.txt"}
local chnroute6_url =  uci:get(name, "@global_rules[0]", "chnroute6_url") or {"https://ispip.clang.cn/all_cn_ipv6.txt"}
local chnlist_url = uci:get(name, "@global_rules[0]", "chnlist_url") or {"https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/accelerated-domains.china.conf","https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/apple.china.conf","https://fastly.jsdelivr.net/gh/felixonmars/dnsmasq-china-list/google.china.conf"}
local geoip_url =  uci:get(name, "@global_rules[0]", "geoip_url") or "https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat"
local geosite_url =  uci:get(name, "@global_rules[0]", "geosite_url") or "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
local asset_location = uci:get(name, "@global_rules[0]", "v2ray_location_asset") or "/usr/share/v2ray/"
local use_nft = uci:get(name, "@global_forwarding[0]", "use_nft") or "0"
local geo2rule = uci:get(name, "@global_rules[0]", "geo2rule") or "0"
local geoip_update_ok, geosite_update_ok = false, false
asset_location = asset_location:match("/$") and asset_location or (asset_location .. "/")

--兼容旧版本geo下载方式的配置，择机删除。
if geoip_url:match(".*/([^/]+)$") == "latest" then
	geoip_url = "https://github.com/Loyalsoldier/geoip/releases/latest/download/geoip.dat"
end
if geosite_url:match(".*/([^/]+)$") == "latest" then
	geosite_url = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
end

if arg3 == "cron" then
	arg2 = nil
end

local log = function(...)
	if arg1 then
		if arg1 == "log" then
			api.log(...)
		elseif arg1 == "print" then
			local result = os.date("%Y-%m-%d %H:%M:%S: ") .. table.concat({...}, " ")
			print(result)
		end
	end
end

local function gen_nftset(set_name, ip_type, tmp_file, input_file)
	f = io.open(input_file, "r")
	local element = f:read("*all")
	f:close()

	nft_file, err = io.open(tmp_file, "w")
	nft_file:write('#!/usr/sbin/nft -f\n')
	nft_file:write(string.format('define %s = {%s}\n', set_name, string.gsub(element, "%s*%c+", " timeout 3650d, ")))
	if sys.call(string.format('nft "list set %s %s" >/dev/null 2>&1', nftable_name, set_name)) ~= 0 then
		nft_file:write(string.format('add set %s %s { type %s; flags interval, timeout; timeout 2d; gc-interval 2d; auto-merge; }\n', nftable_name, set_name, ip_type))
	end
	nft_file:write(string.format('add element %s %s $%s\n', nftable_name, set_name, set_name))
	nft_file:close()
	sys.call(string.format('nft -f %s &>/dev/null',tmp_file))
	os.remove(tmp_file)
end

--gen cache for nftset from file
local function gen_cache(set_name, ip_type, input_file, output_file)
	local tmp_dir = "/tmp/"
	local tmp_file = output_file .. "_tmp"
	local tmp_set_name = set_name .. "_tmp"
	gen_nftset(tmp_set_name, ip_type, tmp_file, input_file)
	sys.call(string.format('nft list set %s %s | sed "s/%s/%s/g" | cat > %s', nftable_name, tmp_set_name, tmp_set_name, set_name, output_file))
	sys.call(string.format('nft flush set %s %s', nftable_name, tmp_set_name))
	sys.call(string.format('nft delete set %s %s', nftable_name, tmp_set_name))
end

-- curl
local function curl(url, file, valifile)
	local args = {
		"-skL", "-w %{http_code}", "--retry 3", "--connect-timeout 3", "--max-time 300", "--speed-limit 51200 --speed-time 15"
	}
	if file then
		args[#args + 1] = "-o " .. file
	end
	if valifile then
		args[#args + 1] = "--dump-header " .. valifile
	end
	local return_code, result = api.curl_auto(url, nil, args)
	return tonumber(result)
end

--check excluded domain
local function check_excluded_domain(value)
	value = value and value:lower() or ""
	for _, domain in ipairs(excluded_domain) do
		local pattern = "^[a-z0-9-]+%.(" .. domain .. ")$"
		if value:match(pattern) then
		    return true
		end
	end
end

local function line_count(file_path)
	local num = 0
	for _ in io.lines(file_path) do
		num = num + 1
	end
	return num;
end

local function non_file_check(file_path, vali_file)
	if fs.readfile(file_path, 10) then
		local size_str = sys.exec("grep -i 'Content-Length' " .. vali_file .. " | tail -n1 | sed 's/[^0-9]//g'")
		local remote_file_size = tonumber(size_str ~= "" and size_str or nil)
		local local_file_size = tonumber(fs.stat(file_path, "size"))
		if remote_file_size and local_file_size then
			if remote_file_size == local_file_size then
				return nil;
			else
				log("下载文件大小校验出错，原始文件大小" .. remote_file_size .. "B，下载文件大小：" .. local_file_size .. "B。")
				return true;
			end
		else
			return nil;
		end
	else
		log("下载文件读取出错。")
		return true;
	end
end

local function GeoToRule(rule_name, rule_type, out_path)
	if not api.is_finded("geoview") then
		log(rule_name .. "生成失败，缺少 geoview 组件。")
		return false;
	end
	local geosite_path = asset_location .. "geosite.dat"
	local geoip_path = asset_location .. "geoip.dat"
	local file_path = (rule_type == "domain") and geosite_path or geoip_path
	local arg
	if rule_type == "domain" then
		if rule_name == "gfwlist" then
			arg = "-type geosite -list gfw"
		else
			arg = "-type geosite -list cn"
		end
	elseif rule_type == "ip4" then
		arg = "-type geoip -list cn -ipv6=false"
	elseif rule_type == "ip6" then
		arg = "-type geoip -list cn -ipv4=false"
	end
	cmd = string.format("geoview -input '%s' %s -lowmem=true -output '%s'", file_path, arg, out_path)
	sys.exec(cmd)
	return true;
end

--fetch rule
local function fetch_rule(rule_name,rule_type,url,exclude_domain)
	local sret = 200
	local sret_tmp = 0
	local domains = {}
	local file_tmp = "/tmp/" ..rule_name.. "_tmp"
	local vali_file = "/tmp/" ..rule_name.. "_vali"
	local download_file_tmp = "/tmp/" ..rule_name.. "_dl"
	local unsort_file_tmp = "/tmp/" ..rule_name.. "_unsort"

	if geo2rule == "1" then
		url = {"geo2rule"}
		log(rule_name.. " 开始生成...")
	else
		log(rule_name.. " 开始更新...")
	end
	for k,v in ipairs(url) do
		if v ~= "geo2rule" then
			sret_tmp = curl(v, download_file_tmp..k, vali_file..k)
			if sret_tmp == 200 and non_file_check(download_file_tmp..k, vali_file..k) then
				log(rule_name.. " 第" ..k.. "条规则:" ..v.. "下载文件过程出错，尝试重新下载。")
				os.remove(download_file_tmp..k)
				os.remove(vali_file..k)
				sret_tmp = curl(v, download_file_tmp..k, vali_file..k)
				if sret_tmp == 200 and non_file_check(download_file_tmp..k, vali_file..k) then
					sret = 0
					sret_tmp = 0
					log(rule_name.. " 第" ..k.. "条规则:" ..v.. "下载文件过程出错，请检查网络或下载链接后重试！")
				end
			end
		else
			if not GeoToRule(rule_name, rule_type, download_file_tmp..k) then return 1 end
			sret_tmp = 200
		end

		if sret_tmp == 200 then
			if rule_name == "gfwlist" and geo2rule == "0" then
				local domains = {}
				local gfwlist = io.open(download_file_tmp..k, "r")
				local decode = api.base64Decode(gfwlist:read("*all"))
				gfwlist:close()

				gfwlist = io.open(download_file_tmp..k, "w")
				gfwlist:write(decode)
				gfwlist:close()
			end

			if rule_type == "domain" and exclude_domain == true then
				for line in io.lines(download_file_tmp..k) do
					line = line:gsub("full:", "")
					if not (string.find(line, comment_pattern) or string.find(line, ip_pattern) or check_excluded_domain(line) or string.find(line, ":")) then
						local match = string.match(line, domain_pattern)
						if match then
							domains[match] = true
						end
					end
				end

			elseif rule_type == "domain" then
				for line in io.lines(download_file_tmp..k) do
					line = line:gsub("full:", "")
					if not (string.find(line, comment_pattern) or string.find(line, ip_pattern) or string.find(line, ":")) then
						local match = string.match(line, domain_pattern)
						if match then
							domains[match] = true
						end
					end
				end

			elseif rule_type == "ip4" then
				local out = io.open(unsort_file_tmp, "a")
				for line in io.lines(download_file_tmp..k) do
					if string.match(line, ip4_ipset_pattern) and not string.match(line, "^0%..*") then
						out:write(string.format("%s\n", line))
					end
				end
				out:close()

			elseif rule_type == "ip6" then
				local out = io.open(unsort_file_tmp, "a")
				for line in io.lines(download_file_tmp..k) do
					if string.match(line, ip6_ipset_pattern) and not string.match(line, "^::(/%d+)?$") then
						out:write(string.format("%s\n", line))
					end
				end
				out:close()

			end
		else
			sret = 0
			log(rule_name.. " 第" ..k.. "条规则:" ..v.. "下载失败，请检查网络或下载链接后重试！")
		end
		os.remove(download_file_tmp..k)
		os.remove(vali_file..k)
	end

	if sret == 200 then
		if rule_type == "domain" then
			local out = io.open(unsort_file_tmp, "w")
			for k,v in pairs(domains) do
				out:write(string.format("%s\n", k))
			end
			out:close()
		end
		sys.call("LC_ALL=C sort -u " .. unsort_file_tmp .. " > " .. file_tmp)
		os.remove(unsort_file_tmp)

		local old_md5 = sys.exec("echo -n $(md5sum " .. rule_path .. "/" ..rule_name.. " | awk '{print $1}')"):gsub("\n", "")
		local new_md5 = sys.exec("echo -n $([ -f '" ..file_tmp.. "' ] && md5sum " ..file_tmp.." | awk '{print $1}')"):gsub("\n", "")
		if old_md5 ~= new_md5 then
			local count = line_count(file_tmp)
			if use_nft == "1" and (rule_type == "ip6" or rule_type == "ip4") then
				local output_file = file_tmp.. ".nft"
				if rule_type == "ip4" then
					local set_name = "passwall_" ..rule_name
					if rule_name == "chnroute" then
						set_name = "passwall_chn"
					end
					gen_cache(set_name, "ipv4_addr", file_tmp, output_file)
				elseif rule_type == "ip6" then
					local set_name = "passwall_" ..rule_name
					if rule_name == "chnroute6" then
						set_name = "passwall_chn6"
					end
					gen_cache(set_name, "ipv6_addr", file_tmp, output_file)
				end
				sys.exec(string.format('mv -f %s %s', output_file, rule_path .. "/" ..rule_name.. ".nft"))
				os.remove(output_file)
			end
			sys.exec("mv -f "..file_tmp .. " " ..rule_path .. "/" ..rule_name)
			reboot = 1
			log(rule_name.. " 更新成功，总规则数 " ..count.. " 条。")
		else
			log(rule_name.. " 版本一致，无需更新。")
		end
	else
		log(rule_name.. " 文件下载失败！")
	end
	os.remove(file_tmp)
	return 0
end

local function fetch_geofile(geo_name, geo_type, url)
	local tmp_path = "/tmp/" .. geo_name
	local asset_path = asset_location .. geo_name
	local down_filename = url:match("^.*/([^/?#]+)")
	local sha_url = url:gsub(down_filename, down_filename .. ".sha256sum")
	local sha_path = tmp_path .. ".sha256sum"
	local vali_file = tmp_path .. ".vali"

	local function verify_sha256(sha_file)
		return sys.call("sha256sum -c " .. sha_file .. " > /dev/null 2>&1") == 0
	end

	local sha_verify = curl(sha_url, sha_path) == 200
	if sha_verify then
		local f = io.open(sha_path, "r")
		if f then
			local content = f:read("*l")
			f:close()
			if content then
				content = content:gsub(down_filename, tmp_path)
				f = io.open(sha_path, "w")
				if f then
					f:write(content)
					f:close()
				end
			end
		end
		if fs.access(asset_path) then
			sys.call(string.format("cp -f %s %s", asset_path, tmp_path))
			if verify_sha256(sha_path) then
				log(geo_type .. " 版本一致，无需更新。")
				return 0
			end
		end
	end

	local sret_tmp = curl(url, tmp_path, vali_file)
	if sret_tmp == 200 and non_file_check(tmp_path, vali_file) then
		log(geo_type .. " 下载文件过程出错，尝试重新下载。")
		os.remove(tmp_path)
		os.remove(vali_file)
		sret_tmp = curl(url, tmp_path, vali_file)
		if sret_tmp == 200 and non_file_check(tmp_path, vali_file) then
			sret_tmp = 0
			log(geo_type .. " 下载文件过程出错，请检查网络或下载链接后重试！")
		end
	end
	if sret_tmp == 200 then
		if sha_verify then
			if verify_sha256(sha_path) then
				sys.call(string.format("mkdir -p %s && cp -f %s %s", asset_location, tmp_path, asset_path))
				reboot = 1
				log(geo_type .. " 更新成功。")
				if geo_type == "geoip" then
					geoip_update_ok = true
				else
					geosite_update_ok = true
				end
			else
				log(geo_type .. " 更新失败，请稍后重试或更换更新URL。")
				return 1
			end
		else
			if fs.access(asset_path) and sys.call(string.format("cmp -s %s %s", tmp_path, asset_path)) == 0 then
				log(geo_type .. " 版本一致，无需更新。")
				return 0
			end
			sys.call(string.format("mkdir -p %s && cp -f %s %s", asset_location, tmp_path, asset_path))
			reboot = 1
			log(geo_type .. " 更新成功。")
			if geo_type == "geoip" then
				geoip_update_ok = true
			else
				geosite_update_ok = true
			end
		end
	else
		log(geo_type .. " 更新失败，请稍后重试或更换更新URL。")
		return 1
	end
	return 0
end

local function fetch_gfwlist()
	fetch_rule("gfwlist","domain",gfwlist_url,true)
end

local function fetch_chnroute()
	fetch_rule("chnroute","ip4",chnroute_url,false)
end

local function fetch_chnroute6()
	fetch_rule("chnroute6","ip6",chnroute6_url,false)
end

local function fetch_chnlist()
	fetch_rule("chnlist","domain",chnlist_url,false)
end

local function fetch_geoip()
	fetch_geofile("geoip.dat","geoip",geoip_url)
end

local function fetch_geosite()
	fetch_geofile("geosite.dat","geosite",geosite_url)
end

if arg2 then
	string.gsub(arg2, '[^' .. "," .. ']+', function(w)
		if w == "gfwlist" then
			gfwlist_update = "1"
		end
		if w == "chnroute" then
			chnroute_update = "1"
		end
		if w == "chnroute6" then
			chnroute6_update = "1"
		end
		if w == "chnlist" then
			chnlist_update = "1"
		end
		if w == "geoip" then
			geoip_update = "1"
		end
		if w == "geosite" then
			geosite_update = "1"
		end
	end)
else
	gfwlist_update = uci:get(name, "@global_rules[0]", "gfwlist_update") or "1"
	chnroute_update = uci:get(name, "@global_rules[0]", "chnroute_update") or "1"
	chnroute6_update = uci:get(name, "@global_rules[0]", "chnroute6_update") or "1"
	chnlist_update = uci:get(name, "@global_rules[0]", "chnlist_update") or "1"
	geoip_update = uci:get(name, "@global_rules[0]", "geoip_update") or "1"
	geosite_update = uci:get(name, "@global_rules[0]", "geosite_update") or "1"
end
if gfwlist_update == "0" and chnroute_update == "0" and chnroute6_update == "0" and chnlist_update == "0" and geoip_update == "0" and geosite_update == "0" then
	os.exit(0)
end

log("开始更新规则...")
local function safe_call(func, err_msg)
	xpcall(func, function(e)
		log(e)
		log(debug.traceback())
		log(err_msg)
	end)
end

local function remove_tmp_geofile(name)
	os.remove("/tmp/" .. name .. ".dat")
	os.remove("/tmp/" .. name .. ".dat.sha256sum")
	os.remove("/tmp/" .. name .. ".dat.vali")
end

if geo2rule == "1" then
	if geoip_update == "1" then
		log("geoip 开始更新...")
		safe_call(fetch_geoip, "更新geoip发生错误...")
		remove_tmp_geofile("geoip")
	end

	if geosite_update == "1" then
		log("geosite 开始更新...")
		safe_call(fetch_geosite, "更新geosite发生错误...")
		remove_tmp_geofile("geosite")
	end

	if geoip_update_ok then
		safe_call(fetch_chnroute, "生成chnroute发生错误...")
		safe_call(fetch_chnroute6, "生成chnroute6发生错误...")
	end

	if geosite_update_ok then
		safe_call(fetch_gfwlist, "生成gfwlist发生错误...")
		safe_call(fetch_chnlist, "生成chnlist发生错误...")
	end
else
	if gfwlist_update == "1" then
		safe_call(fetch_gfwlist, "更新gfwlist发生错误...")
	end

	if chnroute_update == "1" then
		safe_call(fetch_chnroute, "更新chnroute发生错误...")
	end

	if chnroute6_update == "1" then
		safe_call(fetch_chnroute6, "更新chnroute6发生错误...")
	end

	if chnlist_update == "1" then
		safe_call(fetch_chnlist, "更新chnlist发生错误...")
	end

	if geoip_update == "1" then
		log("geoip 开始更新...")
		safe_call(fetch_geoip, "更新geoip发生错误...")
		remove_tmp_geofile("geoip")
	end

	if geosite_update == "1" then
		log("geosite 开始更新...")
		safe_call(fetch_geosite, "更新geosite发生错误...")
		remove_tmp_geofile("geosite")
	end
end

uci:set(name, "@global_rules[0]", "gfwlist_update", gfwlist_update)
uci:set(name, "@global_rules[0]", "chnroute_update", chnroute_update)
uci:set(name, "@global_rules[0]", "chnroute6_update", chnroute6_update)
uci:set(name, "@global_rules[0]", "chnlist_update", chnlist_update)
uci:set(name, "@global_rules[0]", "geoip_update", geoip_update)
uci:set(name, "@global_rules[0]", "geosite_update", geosite_update)
api.uci_save(uci, name, true)

if reboot == 1 then
	if arg3 == "cron" then
		if not fs.access("/var/lock/" .. name .. ".lock") then
			sys.call("touch /tmp/lock/" .. name .. "_cron.lock")
		end
	end

	log("重启服务，应用新的规则。")
	uci:set(name, "@global[0]", "flush_set", "1")
	api.uci_save(uci, name, true, true)
end
log("规则更新完毕...\n")
