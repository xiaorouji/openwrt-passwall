local cursor = luci.model.uci.cursor()
local i = "passwall"

local n={}
cursor:foreach(i,"servers",function(e)
	if e.server_type and e.server and e.remarks then
		n[e[".name"]]="%s：[%s] %s"%{e.server_type,e.remarks,e.server}
	end
end)

local key_table = {}   
for key,_ in pairs(n) do table.insert(key_table,key) end 
table.sort(key_table)

m=Map(i)
s=m:section(TypedSection,"auto_switch",translate("Auto Switch"))
s.anonymous = true

o=s:option(Flag,"enable",translate("Enable"))
o.default=0
o.rmempty=false

o=s:option(Value,"testing_time",translate("How often is a diagnosis made"),translate("Units:minutes"))
o.default="10"

o=s:option(DynamicList,"tcp_redir_server",translate("List of alternate TCP forwarding servers"),translate("When there is no server, an automatic reconnect scheme is used"))
for _,key in pairs(key_table) do o:value(key,n[key]) end

return m
