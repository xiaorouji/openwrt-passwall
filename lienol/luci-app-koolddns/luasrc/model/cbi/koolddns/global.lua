local o=require"luci.dispatcher"
local e=require("luci.model.ipkg")
local s=require"nixio.fs"
local e=luci.model.uci.cursor()
local i="koolddns"
local a,t,e
local n={}
a=Map(i,translate("koolddns"),translate("Koolshare DDNS Tool"))
a.template="koolddns/index"
t=a:section(TypedSection,"global",translate("Global Setting"))
t.anonymous=true
t.addremove=false
e=t:option(Flag,"enabled",translate("Enable"))
e.rmempty=false
e=t:option(Value,"time",translate("Update Time"))
e.datatype="uinteger"
e.default=30
e.rmempty=false
t=a:section(TypedSection,"koolddns",translate("Domain List"))
t.anonymous=true
t.addremove=true
t.template="cbi/tblsection"
t.extedit=o.build_url("admin","services","koolddns","config","%s")
function t.create(e,t)
new=TypedSection.create(e,t)
luci.http.redirect(e.extedit:format(new))
end
function t.remove(e,t)
e.map.proceed=true
e.map:del(t)
luci.http.redirect(o.build_url("admin","services","koolddns"))
end
local o=""
e=t:option(DummyValue,"fulldomain",translate("Domain"))
e.width="20%"
e.cfgvalue=function(t,n)
local t=a.uci:get(i,n,"domain")or""
local a=a.uci:get(i,n,"name")or""
if t==""or a==""then return""end
if a=="@"then o=t return o end
o="%s.%s"%{a,t}
return o
end
e=t:option(DummyValue,"service",translate("Service Providers"))
e.width="15%"
e=t:option(DummyValue,"interface",translate("Interface"))
e.width="15%"
e=t:option(DummyValue,"interfaceip",translate("Interface").." IP")
e.width="15%"
e.template="koolddns/url"
e.cfgvalue=function(t,o)
local t=a.uci:get(i,o,"interface")or""
local a=a.uci:get(i,o,"ipurl")or""
if t=="url"then return a end
if t==""then return""end
local t=luci.sys.exec("uci -P /var/state get network.%s.ifname 2>/dev/null"%t)or""
if t==""then return""end
local t=luci.sys.exec("ifconfig %q|grep 'inet addr'|awk '{print $2}'|cut -d: -f2"%t)or""
return t
end
e=t:option(DummyValue,"nslookupip",translate("Nslookup").." IP")
e.width="15%"
e.template="koolddns/domain"
e.cfgvalue=function(t,t)
return o
end
e=t:option(Flag,"enable",translate("Enable State"))
e.width="10%"
e.rmempty=false
t=a:section(TypedSection,"global",translate("Update Log"))
t.anonymous=true
e=t:option(Button,"restart",translate("Manually Update"))
e.inputtitle=translate("Update")
e.inputstyle="reload"
e.write=function()
luci.sys.call("/etc/init.d/koolddns update")
luci.http.redirect(luci.dispatcher.build_url("admin","services","koolddns"))
end
e=t:option(TextValue,"log")
e.rows=20
e.wrap="on"
e.readonly=true
e.cfgvalue=function(t,t)
return s.readfile("/var/log/koolddns.log")or""
end
e.write=function(e,e,e)
end
return a
