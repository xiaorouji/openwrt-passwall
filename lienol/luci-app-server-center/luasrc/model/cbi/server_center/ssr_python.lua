local o = require "luci.dispatcher"
local fs = require "nixio.fs"
local sys = require "luci.sys"
local jsonc = require "luci.jsonc"
local cursor = luci.model.uci.cursor()
local appname = "server_center"
local a,t,e

local mudbjson = jsonc.parse(luci.sys.exec("cat /usr/share/ssr_python/mudb.json"))

a=Map(appname, translate("ShadowsocksR Python Server"))

t=a:section(TypedSection,"global",translate("Global Settings"))
t.anonymous=true
t.addremove=false

e=t:option(DummyValue,"status",translate("Current Condition"))
e.template=appname.."/ssr_python_status"
e.value=translate("Collecting data...")

e=t:option(Flag,"ssr_python_enable",translate("Enable"))
e.rmempty=false

t=a:section(TypedSection,"ssr_python_users",translate("Users Manager"))
t.anonymous=true
t.addremove=true
t.template="cbi/tblsection"
t.extedit=o.build_url("admin","vpn",appname,"ssr_python_config","%s")
function t.create(e,t)
	local e=TypedSection.create(e,t)
	luci.http.redirect(o.build_url("admin","vpn",appname,"ssr_python_config",e))
end

function t.remove(t,a)
	t.map.proceed=true
	t.map:del(a)
	luci.http.redirect(o.build_url("admin","vpn",appname,"ssr_python"))
end

e=t:option(Flag, "enable", translate("Enable"))
e.width="5%"
e.rmempty = false

e=t:option(DummyValue,"remarks",translate("Remarks"))
e.width="10%"

e=t:option(DummyValue,"port",translate("Port"))
e.width="10%"

e=t:option(DummyValue,"forbidden_port",translate("Forbidden Port"))
e.width="10%"
e.cfgvalue=function(t,n)
	local str = translate("Null")
	local forbidden_port = a.uci:get(appname,n,"forbidden_port")
	if forbidden_port then
		str=forbidden_port
	end
	return str
end

e=t:option(DummyValue,"device_limit",translate("Device Limit"))
e.width="10%"

e=t:option(DummyValue,"speed_limit_per_con",translate("Speed Limit Per Con"))
e.width="10%"
e.cfgvalue=function(t,n)
	local str = a.uci:get(appname,n,"speed_limit_per_con")
	if tonumber(str) == 0 then
		return translate("No Speed Limit")
	end
	return str.."Kb/s"
end

e=t:option(DummyValue,"speed_limit_per_user",translate("Speed Limit Per User"))
e.width="10%"
e.cfgvalue=function(t,n)
	local str = a.uci:get(appname,n,"speed_limit_per_user")
	if tonumber(str) == 0 then
		return translate("No Speed Limit")
	end
	return str.."Kb/s"
end

e=t:option(DummyValue,"transfer_enable",translate("Available Total Flow"))
e.width="10%"
e.cfgvalue=function(t,section)
	local result = a.uci:get(appname,section,"transfer_enable")
	if result and tonumber(result) == 0 then
		return translate("Infinite")
	else
		return result.."G"
	end
end

--[[e=t:option(DummyValue,"u",translate("Used Upload Traffic"))
e.width="10%"
e.cfgvalue=function(t,section)
	local result = translate("Null")
	if mudbjson then
		for index,object in pairs(mudbjson) do
			if object.id == section then
				local u = object.u
				if u < 1024 then result = u.."B"
				elseif u < 1024*1024 then result = math.ceil((u/1024)).."KB"
				elseif u < 1024*1024*1024 then result = math.ceil((u/1024/1024)).."MB"
				elseif u < 1024*1024*1024*1024 then result = math.ceil((u/1024/1024/1024)).."TB" end
			end
		end
	end
	return result
end

e=t:option(DummyValue,"d",translate("Used Download Traffic"))
e.width="10%"
e.cfgvalue=function(t,section)
	local result = translate("Null")
	if mudbjson then
		for index,object in pairs(mudbjson) do
			if object.id == section then
				local d = object.d
				if d < 1024 then result = d.."B"
				elseif d < 1024*1024 then result = math.ceil((d/1024)).."KB"
				elseif d < 1024*1024*1024 then result = math.ceil((d/1024/1024)).."MB"
				elseif d < 1024*1024*1024*1024 then result = math.ceil((d/1024/1024/1024)).."TB" end
			end
		end
	end
	return result
end]]--

e=t:option(DummyValue,"used_total_traffic",translate("Used Total traffic"))
e.width="10%"
e.cfgvalue=function(t,section)
	local result = translate("Null")
	if mudbjson then
		for index,object in pairs(mudbjson) do
			if object.id == section then
				local count = object.d + object.u
				if count < 1024 then result = count.."B"
				elseif count < 1024*1024 then result = math.ceil((count/1024)).."KB"
				elseif count < 1024*1024*1024 then result = math.ceil((count/1024/1024)).."MB"
				elseif count < 1024*1024*1024*1024 then result = math.ceil((count/1024/1024/1024)).."TB" end
			end
		end
	end
	return result
end

e=t:option(DummyValue,"status",translate("Status"))
e.template="server_center/ssr_python_users_status"
e.width="20%"

a:append(Template(appname.."/ssr_python"))
a:append(Template(appname.."/ssr_python_users_list_status"))

return a