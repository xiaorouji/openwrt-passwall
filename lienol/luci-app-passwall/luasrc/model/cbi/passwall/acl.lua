local sys=require"luci.sys"
local webadmin=require"luci.tools.webadmin"
m=Map("passwall")
s=m:section(TypedSection,"acl_rule",translate("ACLs"),
translate("ACLs is a tools which used to designate specific IP proxy mode"))
s.template="cbi/tblsection"
s.sortable=true
s.anonymous=true
s.addremove=true

o=s:option(Flag,"enabled",translate("Enable"))
o.rmempty=false

o=s:option(Value,"aclremarks",translate("ACL Remarks"))
o.rmempty=true

o=s:option(Value,"ipaddr",translate("IP Address"))
o.datatype="ip4addr"
o.rmempty=true
webadmin.cbi_add_knownips(o)

o=s:option(Value,"macaddr",translate("MAC Address"))
o.rmempty=true
sys.net.mac_hints(function(e,t)
o:value(e,"%s (%s)"%{e,t})
end)

o=s:option(ListValue,"proxy_mode",translate("Proxy Mode"))
o.default="disable"
o.rmempty=false
o:value("disable",translate("No Proxy"))
o:value("global",translate("Global Proxy"))
o:value("gfwlist",translate("GFW List"))
o:value("chnroute",translate("China WhiteList"))
o:value("gamemode",translate("Game Mode"))
o:value("returnhome",translate("Return Home"))
o=s:option(Value,"ports",translate("Dest Ports"))
o.placeholder="80,443"
return m
