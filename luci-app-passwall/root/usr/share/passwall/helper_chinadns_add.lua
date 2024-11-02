require 'nixio'
local api = require "luci.passwall.api"
local appname = "passwall"

local var = api.get_args(arg)
local FLAG = var["-FLAG"]
local USE_DIRECT_LIST = var["-USE_DIRECT_LIST"]
local USE_PROXY_LIST = var["-USE_PROXY_LIST"]

local TMP_PATH = "/tmp/etc/" .. appname

if not nixio.fs.access(TMP_PATH) then
	nixio.fs.mkdir(TMP_PATH, 493)
end

local tmp_direct_host = TMP_PATH .. "/direct_host"
if USE_DIRECT_LIST == "1" and not nixio.fs.access(tmp_direct_host) then
	local direct_domain = {}
	for line in io.lines("/usr/share/passwall/rules/direct_host") do
		line = api.get_std_domain(line)
		if line ~= "" and not line:find("#") then
			table.insert(direct_domain, line)
		end
	end
	if #direct_domain > 0 then
		local direct_out = io.open(tmp_direct_host, "a")
		for i = 1, #direct_domain do
			direct_out:write(direct_domain[i] .. "\n")
		end
		direct_out:close()
	end
end

local tmp_proxy_host = TMP_PATH .. "/proxy_host"
if USE_PROXY_LIST == "1" and not nixio.fs.access(tmp_proxy_host) then
	local proxy_domain = {}
	for line in io.lines("/usr/share/passwall/rules/proxy_host") do
		line = api.get_std_domain(line)
		if line ~= "" and not line:find("#") then
			table.insert(proxy_domain, line)
		end
	end
	if #proxy_domain > 0 then
		local proxy_out = io.open(tmp_proxy_host, "a")
		for i = 1, #proxy_domain do
			proxy_out:write(proxy_domain[i] .. "\n")
		end
		proxy_out:close()
	end
end
