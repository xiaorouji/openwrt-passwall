local o = require "luci.dispatcher"
local fs = require "nixio.fs"
local sys = require "luci.sys"
local cursor = luci.model.uci.cursor()
local appname = "passwall_server"
local a,t,e

a=Map(appname)

t=a:section(TypedSection,"global",translate("General settings"))
t.anonymous=true
t.addremove=false

e=t:option(Flag,"v2ray_enable",translate("Enable"))
e.rmempty=false

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
e.template="passwall_server/v2ray_status"
e.width="20%"

a:append(Template("passwall_server/server_list_v2ray_status"))

return a
