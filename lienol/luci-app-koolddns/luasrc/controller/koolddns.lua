module("luci.controller.koolddns",package.seeall)
function index()
if not nixio.fs.access("/etc/config/koolddns")then
return
end
entry({"admin","services","koolddns"},cbi("koolddns/global"),_("Koolddns"),1).dependent=true
entry({"admin","services","koolddns","config"},cbi("koolddns/config")).leaf=true
entry({"admin","services","koolddns","nslookup"},call("act_nslookup")).leaf=true
entry({"admin","services","koolddns","curl"},call("act_curl")).leaf=true
end
function act_nslookup()
local e={}
e.index=luci.http.formvalue("index")
e.value=luci.sys.exec("nslookup %q localhost 2>&1|grep 'Address 1:'|tail -n1|cut -d' ' -f3"%luci.http.formvalue("domain"))
luci.http.prepare_content("application/json")
luci.http.write_json(e)
end
function act_curl()
local e={}
e.index=luci.http.formvalue("index")
e.value=luci.sys.exec("curl -s %q 2>&1"%luci.http.formvalue("url"))
luci.http.prepare_content("application/json")
luci.http.write_json(e)
end
