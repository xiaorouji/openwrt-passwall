local d = require "luci.dispatcher"
local appname = "passwall"

m = Map(appname)

-- [[ App Settings ]]--
s = m:section(TypedSection, "global_app", translate("App Update"),
              "<font color='red'>" ..
                  translate("Please confirm that your firmware supports FPU.") ..
                  "</font>")
s.anonymous = true

o = s:option(MultiValue, "show", translate("Show"))
o:value("xray", "Xray")
o:value("v2ray", "V2ray")
o:value("trojan-go", "Trojan-Go")
o:value("kcptun", "Kcptun")
o:value("brook", "Brook")

local show = m:get("@global_app[0]", "show") or ""

if show:find("xray") then
    s:append(Template(appname .. "/app_update/xray_version"))
    o = s:option(Value, "xray_file", translatef("%s App Path", "Xray"))
    o.default = "/usr/bin/xray"
    o.rmempty = false
end

if show:find("v2ray") then
    s:append(Template(appname .. "/app_update/v2ray_version"))
    o = s:option(Value, "v2ray_file", translatef("%s App Path", "V2ray"))
    o.default = "/usr/bin/v2ray"
    o.rmempty = false
end

if show:find("trojan%-go") then
    s:append(Template(appname .. "/app_update/trojan_go_version"))
    o = s:option(Value, "trojan_go_file", translatef("%s App Path", "Trojan-Go"))
    o.default = "/usr/bin/trojan-go"
    o.rmempty = false

    o = s:option(Value, "trojan_go_latest", translatef("Trojan-Go Version API"), translate("alternate API URL for version checking"))
    o.default = "https://api.github.com/repos/peter-tank/trojan-go/releases/latest"
end

if show:find("kcptun") then
    s:append(Template(appname .. "/app_update/kcptun_version"))
    o = s:option(Value, "kcptun_client_file", translatef("%s Client App Path", "Kcptun"))
    o.default = "/usr/bin/kcptun-client"
    o.rmempty = false
end

if show:find("brook") then
    s:append(Template(appname .. "/app_update/brook_version"))
    o = s:option(Value, "brook_file", translatef("%s App Path", "Brook"))
    o.default = "/usr/bin/brook"
    o.rmempty = false
end

o = s:option(DummyValue, "tips", " ")
o.rawhtml = true
o.cfgvalue = function(t, n)
    return string.format('<font color="red">%s</font>', translate("if you want to run from memory, change the path, /tmp beginning then save the application and update it manually."))
end

return m
