local e=require"nixio.fs"
local e=require"luci.sys"
--local t=luci.sys.exec("cat /usr/share/passwall/dnsmasq.d/gfwlist.conf|grep -c ipset")
local a=luci.sys.exec("/usr/bin/kcptun_client -v | awk '{print $3}'")

m=Map("passwall")
-- [[ Rule Settings ]]--
s=m:section(TypedSection,"global_rules",translate("Rule status"))
s.anonymous=true
s:append(Template("passwall/rule_version"))

o=s:option(Flag,"auto_update",translate("Enable auto update rules"))
o.default=0
o.rmempty=false

o=s:option(ListValue,"week_update",translate("Week update rules"))
o:value(7,translate("Every day"))
for e=1,6 do
o:value(e,translate("Week")..e)
end
o:value(0,translate("Week")..translate("day"))
o.default=0
o:depends("auto_update",1)

o=s:option(ListValue,"time_update",translate("Day update rules"))
for e=0,23 do
o:value(e,e..translate("oclock"))
end
o.default=0
o:depends("auto_update",1)

-- [[ Kcptun Settings ]]--
s=m:section(TypedSection,"global_kcptun",translate("Kcptun Update"))
s.anonymous=true

o=s:option(DummyValue,"satus22",nil,translate("Current Kcptun client version is")..
"【 "..a.."】，<font style='color:red'>"..
translate("The Kcptun server and client should use the same version number, otherwise they may not be able to connect!")..
"</font>")

o=s:option(Value,"kcptun_client_file",translate("Kcptun client path"))
o.default="/usr/bin/kcptun_client"
o.rmempty=false
o = s:option(Button, "_check_kcptun", translate("Manually update"),
	translate("Make sure there is enough space to install Kcptun"))
o.template = "passwall/kcptun"
o.inputstyle = "apply"
o.btnclick = "onKcptunBtnClick('kcptun', this);"
o.id = "_kcptun-check_kcptun"

-- [[ Subscribe Settings ]]--
s=m:section(TypedSection,"global_subscribe",translate("SSR Server Subscribe"))
s.anonymous=true

o=s:option(DynamicList,"baseurl",translate("Subscribe URL"),translate("Servers unsubscribed will be deleted in next update; Please summit the Subscribe URL first before manually update."))

o=s:option(Button,"_update",translate("Manually update"))
o.inputstyle="apply"
function o.write(e,e)
luci.sys.exec("/usr/share/passwall/onlineconfig.sh")
luci.http.redirect(luci.dispatcher.build_url("admin","vpn","passwall","log"))
end
o=s:option(Button,"_stop",translate("Delete All Subscribe"))
o.inputstyle="apply"
function o.write(e,e)
luci.sys.exec("/usr/share/passwall/onlineconfig.sh stop")
luci.http.redirect(luci.dispatcher.build_url("admin","vpn","passwall","log"))
end

o=s:option(Flag,"subscribe_by_ss",translate("Subscribe via proxy"))
o.default=0
o.rmempty=false

o=s:option(Flag,"auto_update_subscribe",translate("Enable auto update subscribe"))
o.default=0
o.rmempty=false

o=s:option(ListValue,"week_update_subscribe",translate("Week update rules"))
o:value(7,translate("Every day"))
for e=1,6 do
o:value(e,translate("Week")..e)
end
o:value(0,translate("Week")..translate("day"))
o.default=0
o:depends("auto_update_subscribe",1)

o=s:option(ListValue,"time_update_subscribe",translate("Day update rules"))
for e=0,23 do
o:value(e,e..translate("oclock"))
end
o.default=0
o:depends("auto_update_subscribe",1)

-- [[ SS/SSR link Settings ]]--
s=m:section(TypedSection,"global",translate("Add the server via the SS/SSR link"))
s.anonymous=true

local i="/usr/share/passwall/ssr_link.conf"
o=s:option(TextValue,"ssr_link",translate("SS/SSR Link"),translate("Please fill in the SS/SSR link and then click Add; each line of a link."))
o.rows=1
o.wrap="off"
o.cfgvalue=function(s,s)
return nixio.fs.readfile(i)or""
end
o.write=function(s,s,o)
nixio.fs.writefile("/tmp/ssr_link",o:gsub("\r\n","\n"))
if(luci.sys.call("cmp -s /tmp/ssr_link /usr/share/passwall/ssr_link.conf")==1)then
nixio.fs.writefile(i,o:gsub("\r\n","\n"))
end
nixio.fs.remove("/tmp/ssr_link")
end

o=s:option(Button,"_add",translate("Add Server"))
o.inputtitle=translate("Add")
o.inputstyle="apply"
function o.write(e,e)
luci.sys.exec("/usr/share/passwall/onlineconfig.sh add")
end
return m
