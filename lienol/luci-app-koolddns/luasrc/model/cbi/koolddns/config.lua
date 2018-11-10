local n="koolddns"
local i=require"luci.dispatcher"
local o=require"luci.model.network".init()
local a,t,e
arg[1]=arg[1]or""
a=Map(n,translate("DDNS Config"))
a.redirect=i.build_url("admin","services","koolddns")
t=a:section(NamedSection,arg[1],"koolddns","")
t.addremove=false
t.dynamic=false
e=t:option(ListValue,"enable",translate("Enable State"))
e.default="1"
e.rmempty=false
e:value("1",translate("Enable"))
e:value("0",translate("Disable"))
e=t:option(Value,"domain",translate("Main Domain"))
e.datatype="host"
e.rmempty=false
e=t:option(Value,"name",translate("Sub Domain"))
e.rmempty=false
e=t:option(ListValue,"service",translate("Service Providers"))
e:value("aliddns",translate("AliDDNS"))
e:value("dnspod",translate("DNSPOD"))
e.rmempty=false
e=t:option(Value,"accesskey",translate("Access Key"))
e.rmempty=false
e=t:option(Value,"signature",translate("Signature"))
e.rmempty=false
e=t:option(Value,"interface",translate("Interface"))
e.rmempty=false
e:value("url",translate("Use the URL to obtain the public IP"))
for a,t in ipairs(o:get_networks())do
if t:name()~="loopback"then e:value(t:name())end
end
e=t:option(Value,"ipurl",translate("Internet Site"))
e:depends("interface","url")
e.default="whatismyip.akamai.com"
e=t:option(Value,"urlinterface",translate("urlInterface"))
e:depends("interface","url")
for a,t in ipairs(o:get_networks())do
if t:name()~="loopback"then e:value(t:name())end
end
return a
