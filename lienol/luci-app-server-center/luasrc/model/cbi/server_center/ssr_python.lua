local o = require "luci.dispatcher"
local fs = require "nixio.fs"
local sys = require "luci.sys"
local cjson = require "cjson"
local cursor = luci.model.uci.cursor()
local appname = "server_center"
local a,t,e

local mudbjson = cjson.decode(luci.sys.exec("cat /usr/share/ssr_python/mudb.json"))

a=Map(appname, translate("ShadowsocksR Python Server"))

t=a:section(TypedSection,"global",translate("Global Settings"))
t.anonymous=true
t.addremove=false

e=t:option(DummyValue,"status",translate("Current Condition"))
e.template=appname.."/ssr_python_status"
e.value=translate("Collecting data...")

e=t:option(Flag,"ssr_python_enable",translate("Enable"))
e.rmempty=false

e=t:option(Flag,"ssr_python_auto_clear_transfer",translate("Enable Auto Clear Traffic"))
e.default=0
e.rmempty=false

e=t:option(Value,"ssr_python_auto_clear_transfer_time",translate("Clear Traffic Time Interval"),translate("*,*,*,*,* is Min Hour Day Mon Week"))
e.default="0,2,1,*,*"
e:depends("ssr_python_auto_clear_transfer",1)

e=t:option(Button,"clear_transfer",translate("Clear All Users Traffic"))
e.inputstyle="remove"
function e.write(t,section)
	local url=luci.dispatcher.build_url("admin", "vpn", "server_center", "ssr_python_clear_traffic_all_users")
	e.description = "<script>if (confirm('确认吗？')==true){XHR.get('"..url.."',null,function(x,result){window.location.replace(window.location.href)})}</script>"
end

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

e=t:option(DummyValue,"status",translate("Status"))
e.template="server_center/ssr_python_users_status"
e.width="5%"

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
	local str = translate("No Speed Limit")
	local speed_limit_per_con = a.uci:get(appname,n,"speed_limit_per_con")
	if speed_limit_per_con and tonumber(speed_limit_per_con) > 0 then
		speed_limit_per_con = tonumber(speed_limit_per_con)
		if speed_limit_per_con < 1024 then str = speed_limit_per_con.."Kb/s"
		elseif speed_limit_per_con < 1024*1024 then str = string.format("%0.2f",speed_limit_per_con/1024).."Mb/s" end
	end
	return str
end

e=t:option(DummyValue,"speed_limit_per_user",translate("Speed Limit Per User"))
e.width="10%"
e.cfgvalue=function(t,n)
	local str = translate("No Speed Limit")
	local speed_limit_per_user = a.uci:get(appname,n,"speed_limit_per_user")
	if speed_limit_per_user and tonumber(speed_limit_per_user) > 0 then
		speed_limit_per_user = tonumber(speed_limit_per_user)
		if speed_limit_per_user < 1024 then str = speed_limit_per_user.."Kb/s"
		elseif speed_limit_per_user < 1024*1024 then str = string.format("%0.2f",speed_limit_per_user/1024).."Mb/s" end
	end
	return str
end

e=t:option(DummyValue,"transfer_enable",translate("Available Total Flow"))
e.width="10%"
e.cfgvalue=function(t,section)
	local str = translate("Infinite")
	local transfer_enable = a.uci:get(appname,n,"transfer_enable")
	if transfer_enable and tonumber(transfer_enable) > 0 then
		str = transfer_enable.."G"
	end
	return str
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
				elseif u < 1024*1024 then result = string.format("%0.2f",(u/1024)).."KB"
				elseif u < 1024*1024*1024 then result = string.format("%0.2f",(u/1024/1024)).."MB"
				elseif u < 1024*1024*1024*1024 then result = string.format("%0.2f",(u/1024/1024/1024)).."GB"
				elseif u < 1024*1024*1024*1024*1024 then result = string.format("%0.2f",(u/1024/1024/1024/1024)).."TB" end
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
				elseif d < 1024*1024 then result = string.format("%0.2f",(d/1024)).."KB"
				elseif d < 1024*1024*1024 then result = string.format("%0.2f",(d/1024/1024)).."MB"
				elseif d < 1024*1024*1024*1024 then result = string.format("%0.2f",(d/1024/1024/1024)).."GB"
				elseif d < 1024*1024*1024*1024*1024 then result = string.format("%0.2f",(d/1024/1024/1024/1024)).."TB" end
			end
		end
	end
	return result
end]]--

e=t:option(DummyValue,"used_total_traffic",translate("Used Total Traffic"))
e.width="10%"
e.cfgvalue=function(t,section)
	local result = translate("Null")
	if mudbjson then
		for index,object in pairs(mudbjson) do
			if object.id == section then
				local count = object.d + object.u
				if count < 1024 then result = count.."B"
				elseif count < 1024*1024 then result = string.format("%0.2f",(count/1024)).."KB"
				elseif count < 1024*1024*1024 then result = string.format("%0.2f",(count/1024/1024)).."MB"
				elseif count < 1024*1024*1024*1024 then result = string.format("%0.2f",(count/1024/1024/1024)).."GB"
				elseif count < 1024*1024*1024*1024*1024 then result = string.format("%0.2f",(count/1024/1024/1024/1024)).."TB" end
			end
		end
	end
	return result
end

e=t:option(Button,"clear_transfer",translate("Clear Traffic"))
e.inputstyle="remove"
function e.write(t,section)
	local url=luci.dispatcher.build_url("admin", "vpn", "server_center", "ssr_python_clear_traffic")
	e.description = "<script>if (confirm('确认吗？')==true){XHR.get('"..url.."',{id:'"..section.."'},function(x,result){window.location.replace(window.location.href)})}</script>"
end

a:append(Template(appname.."/ssr_python"))
--a:append(Template(appname.."/ssr_python_users_list_status"))

return a