local o=require "luci.dispatcher"
local fs=require "nixio.fs"
local sys=require "luci.sys"
local cursor=luci.model.uci.cursor()
local i="passwall"
local a,t,e

local n={}
cursor:foreach(i,"servers",function(e)
	local server_type
	if e.server_type == "ssr" then server_type = "SSR"
	elseif e.server_type == "ss" then server_type = "SS"
	elseif e.server_type == "v2ray" then server_type = "V2ray"
	elseif e.server_type == "brook" then server_type = "Brook"
	end
	if e.server_type and e.server and e.remarks then
		n[e[".name"]]="%s：[%s] %s"%{server_type,e.remarks,e.server}
	end
end)

a=Map(i)
a.template="passwall/index"

t=a:section(TypedSection,"servers",translate("Servers List"),translate("Make sure that the KCP parameters are configured under the corresponding SS server to use the KCP fast switch.")..
"<br><font style='color:red'>"..
translate("Note: UDP cannot be forwarded after KCP is turned on.")..
"</font>")
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
	luci.http.redirect(o.build_url("admin","vpn","passwall"))
end

e=t:option(DummyValue,"remarks",translate("Node Remarks"))
e.width="15%"

e=t:option(DummyValue,"server_type",translate("Server Type"))
e.width="10%"
e.cfgvalue=function(t,n)
local t=a.uci:get(i,n,"server_type")or""
local b=t
if t=="ssr" then b="SSR"
elseif t=="ss" then b="SS"
elseif t=="v2ray" then b="V2ray"
elseif t=="brook" then b="Brook"
end
return b
end

e=t:option(DummyValue,"server",translate("Server Address"))
e.width="15%"

e=t:option(DummyValue,"server_port",translate("Server Port"))
e.width="10%"

e=t:option(DummyValue,"encrypt_method",translate("Encrypt Method"))
e.width="15%"
e.cfgvalue=function(t,n)
local type=a.uci:get(i,n,"server_type") or ""
if type == "ssr" then
	return a.uci:get(i,n,"ssr_encrypt_method") or ""
elseif type == "ss" then
	return a.uci:get(i,n,"ss_encrypt_method") or ""
elseif type == "v2ray" then
	return a.uci:get(i,n,"v2ray_security") or ""
end
return "无"
end

e=t:option(Flag,"use_kcp",translate("KCPTUN Switch"))
e.width="10%"

e=t:option(DummyValue,"server",translate("Ping Latency"))
e.template="passwall/ping"
e.width="10%"

local apply = luci.http.formvalue("cbi.apply")
if apply then
--os.execute("/etc/init.d/passwall restart")
end

return a
