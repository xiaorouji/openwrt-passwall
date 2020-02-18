local o=require "luci.dispatcher"
local fs=require "nixio.fs"
local sys=require "luci.sys"
local cursor=luci.model.uci.cursor()
local appname="passwall"
local a,t,e

a=Map(appname)

-- [[ SS/SSR link Settings ]]--
t=a:section(TypedSection,"global",translate("Add the server via the SS/SSR link"))
t.anonymous=true

local i="/usr/share/passwall/ssr_link.conf"
e=t:option(TextValue,"ssr_link",translate("SS/SSR Link"),translate("Please fill in the SS/SSR link and then click Add; each line of a link."))
e.wrap="off"
e.cfgvalue=function(s,s)
return nixio.fs.readfile(i)or""
end
e.write=function(s,s,o)
nixio.fs.writefile("/tmp/ssr_link",o:gsub("\r\n","\n"))
if(luci.sys.call("cmp -s /tmp/ssr_link /usr/share/passwall/ssr_link.conf")==1)then
nixio.fs.writefile(i,o:gsub("\r\n","\n"))
end
nixio.fs.remove("/tmp/ssr_link")
end

e=t:option(Button,"_add",translate("Add Server"))
e.inputtitle=translate("Add")
e.inputstyle="add"
function e.write(e,e)
luci.sys.exec("/usr/share/passwall/onlineconfig.sh add")
end

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
e.template="passwall/ping"
e.width="10%"

a:append(Template("passwall/server_list_ping"))

return a
