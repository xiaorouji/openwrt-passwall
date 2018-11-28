local cursor=luci.model.uci.cursor()
local i="passwall"

local n={}
cursor:foreach(i,"servers",function(e)
	if e.server_type and e.server and e.remarks then
		n[e[".name"]]="%s：[%s] %s"%{e.server_type,e.remarks,e.server}
	end
end)

m=Map(i)
s=m:section(TypedSection,"auto_switch",translate("Auto Switch"))
s.anonymous = true

o=s:option(Flag,"disconnect_reconnect_on",translate("Disconnection auto reconnection"),translate("Automatic switching cannot be used when this option is checked"))
o.default=0
o.rmempty=false

o=s:option(Value,"disconnect_reconnect_time",translate("How often is a diagnosis made"),translate("Units:minutes"))
o:depends("disconnect_reconnect_on",1)
o.default="10"
o.rmempty=true

o=s:option(Value,"testing_time",translate("How often is a diagnosis made"),translate("Units:minutes"))
o.default="10"
o.rmempty=true
o:depends("disconnect_reconnect_on",0)

o=s:option(DynamicList,"tcp_redir_server",translate("List of alternate TCP forwarding servers"))
for a,t in pairs(n)do o:value(a,t)end
o:depends("disconnect_reconnect_on",0)

return m
