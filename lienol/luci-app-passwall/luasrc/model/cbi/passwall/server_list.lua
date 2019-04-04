local o = require "luci.dispatcher"
local fs = require "nixio.fs"
local sys = require "luci.sys"
local cursor = luci.model.uci.cursor()
local appname = "passwall"
local a,t,e

a=Map(appname)

-- [[ SS/SSR link Settings ]]--
t=a:section(TypedSection,"global",translate("Add the server via the link"))
t.anonymous=true

t:append(Template("passwall/server_list/link_add_server"))

t=a:section(TypedSection,"servers",translate("Servers List"),translate("Make sure that the Kcptun parameters are configured under the servers to use the Kcptun fast switch."))
t.anonymous=true
t.addremove=true
t.template="cbi/tblsection"
t.extedit=o.build_url("admin","vpn","passwall","serverconfig","%s")
function t.create(e,t)
	local e=TypedSection.create(e,t)
	luci.http.redirect(o.build_url("admin","vpn","passwall","serverconfig",e))
end

function t.remove(t,a)
	t.map.proceed=true
	t.map:del(a)
	luci.http.redirect(o.build_url("admin","vpn","passwall","server_list"))
end

e=t:option(DummyValue,"remarks",translate("Node Remarks"))
e.width="15%"

e=t:option(DummyValue,"server_type",translate("Server Type"))
e.width="10%"

e=t:option(DummyValue,"server",translate("Server Address"))
e.width="15%"

e=t:option(DummyValue,"server_port",translate("Server Port"))
e.width="10%"

e=t:option(DummyValue,"encrypt_method",translate("Encrypt Method"))
e.width="15%"
e.cfgvalue=function(t,n)
local str="无"
local type = a.uci:get(appname,n,"server_type") or ""
if type == "SSR" then
	return a.uci:get(appname,n,"ssr_encrypt_method")
elseif type == "SS" then
	return a.uci:get(appname,n,"ss_encrypt_method")
elseif type == "V2ray" then
	return a.uci:get(appname,n,"v2ray_security")
end
return str
end

e=t:option(Flag,"use_kcp",translate("Kcptun Switch"))
e.width="10%"

e=t:option(DummyValue,"server",translate("Ping Latency"))
e.template="passwall/server_list/ping"
e.width="10%"

e=t:option(DummyValue,"apply",translate("Apply"))
e.width="10%"
e.template="passwall/server_list/apply"

a:append(Template("passwall/server_list/server_list"))

return a
