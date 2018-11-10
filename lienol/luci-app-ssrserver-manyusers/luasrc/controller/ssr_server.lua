module("luci.controller.ssr_server",package.seeall)

function index()
if not nixio.fs.access("/etc/config/ssr_server")then
  return
end

entry({"admin", "vpn"}, firstchild(), "VPN", 45).dependent = false

entry({"admin","vpn","ssr_server"},cbi("ssr_server/index"),_("SSR Server"),46).dependent=true
entry({"admin","vpn","ssr_server","status"},call("act_status")).leaf=true
end

function act_status()
  local e={}
  e.ssr_server_status=luci.sys.call("ps | grep '/usr/bin/python /usr/share/ssr/shadowsocks/server.py' | grep -v grep >/dev/null")==0
  luci.http.prepare_content("application/json")
  luci.http.write_json(e)
end
