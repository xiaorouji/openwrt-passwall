local appname = "passwall_server"
local a,t,e
local m, s
local o=require"nixio.fs"
local methods={
"none",
"table",
"rc4",
"rc4-md5",
"aes-128-cfb",
"aes-192-cfb",
"aes-256-cfb",
"aes-128-ctr",
"aes-192-ctr",
"aes-256-ctr",
"bf-cfb",
"cast5-cfb",
"des-cfb",
"rc2-cfb",
"salsa20",
"chacha20",
"chacha20-ietf",
}
local protocols={
"origin",
"verify_simple",
"verify_deflate",
"verify_sha1",
"auth_simple",
"auth_sha1",
"auth_sha1_v2",
"auth_sha1_v4",
"auth_aes128_md5",
"auth_aes128_sha1",
"auth_chain_a",
"auth_chain_b",
"auth_chain_c",
"auth_chain_d",
}
local obfss={
"plain",
"http_simple",
"http_post",
"random_head",
"tls_simple",
"tls1.0_session_auth",
"tls1.2_ticket_auth",
}

a= Map(appname, translate("ShadowsocksR Python Server"))
a.description = translate("")
a.template=appname.."/ssr_python_server"

t=a:section(TypedSection,"global",translate("Global Setting"))
t.anonymous=true
t.addremove=false

o=t:option(DummyValue,"ssr_python_status",translate("Current Condition"))
o.template=appname.."/ssr_python_server_status"
o.value=translate("Collecting data...")

e=t:option(Flag,"ssr_python_enable",translate("Enable"))
e.rmempty=false

t=a:section(TypedSection,"ssr_python_server",translate("General Settings"))
t.anonymous=true
t.addremove=false

e=t:option(ListValue,"encrypt_method",translate("Encrypt Method"))
for a,t in ipairs(methods)do e:value(t)end
e.rmempty=false

e=t:option(ListValue,"protocol",translate("Protocol"))
for a,t in ipairs(protocols)do e:value(t)end
e.rmempty=false

e=t:option(Value,"protocol_param",translate("Protocol Param"))

e=t:option(ListValue,"obfs",translate("Obfs"))
for a,t in ipairs(obfss)do e:value(t)end
e.rmempty=false

e=t:option(Value,"obfs_param",translate("Obfs Param"))

e=t:option(DynamicList,"redirect",translate("redirect"),translate("Such as")..": *:8388#1.1.1.1:8388")
e.placeholder = "*:8388#1.1.1.1:8388"

e=t:option(Value,"timeout",translate("Time Out"))
e.datatype="uinteger"
e.default=300

e=t:option(ListValue,"fast_open",translate("Fast Open"))
e:value("false")
e:value("true")
e.default='false'

e=a:section(TypedSection,"ssr_python_server_users",translate("Users Manager"))
e.addremove=true
e.anonymous=true
e.template="cbi/tblsection"
o=e:option(Flag,"enabled",translate("Enabled"))
o.rmempty=false
o=e:option(Value,"port",translate("Port"))
o.datatype="port"
o.rmempty=false
o=e:option(Value,"password",translate("Password"))
o.rmempty=false

return a
