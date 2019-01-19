local o = require "luci.dispatcher"
local fs = require "nixio.fs"
local sys = require "luci.sys"
local cursor = luci.model.uci.cursor()
local appname = "server_center"
local a,t,e

a=Map(appname, translate("V2ray Server"))

t=a:section(TypedSection,"global",translate("Global Settings"))
t.anonymous=true
t.addremove=false

e=t:option(Flag,"v2ray_enable",translate("Enable"))
e.rmempty=false

t:append(Template("server_center/v2ray"))

t=a:section(TypedSection,"v2ray_servers",translate("Users Manager"))
t.anonymous=true
t.addremove=true
t.template="cbi/tblsection"
t.extedit=o.build_url("admin","vpn",appname,"v2ray_config","%s")
function t.create(e,t)
	local e=TypedSection.create(e,t)
	luci.http.redirect(o.build_url("admin","vpn",appname,"v2ray_config",e))
end

function t.remove(t,a)
	t.map.proceed=true
	t.map:del(a)
	luci.http.redirect(o.build_url("admin","vpn",appname,"v2ray"))
end

e=t:option(Flag, "enable", translate("Enable"))
e.width="5%"
e.rmempty = false

e=t:option(DummyValue,"remarks",translate("Remarks"))
e.width="15%"

e=t:option(DummyValue,"port",translate("Port"))
e.width="10%"

e=t:option(DummyValue,"protocol",translate("Protocol"))
e.width="15%"

e=t:option(DummyValue,"VMess_id",translate("ID"))
e.width="35%"

e=t:option(DummyValue,"status",translate("Status"))
e.template="server_center/v2ray_users_status"
e.width="20%"

a:append(Template("server_center/v2ray_users_list_status"))

return a
