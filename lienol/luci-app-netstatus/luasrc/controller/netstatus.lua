module("luci.controller.netstatus",package.seeall)

function index()
if not nixio.fs.access("/etc/config/netstatus")then
  return
end

entry({"admin","network","netstatus"},cbi("netstatus"),_("Net Status"),11).dependent=true
entry({"admin","network","netstatus","status"},call("act_status")).leaf=true
end

function act_status()
  local e={}
  e.netstatus_status=luci.sys.call("ps | grep server.py |grep -v grep >/dev/null")==0
  luci.http.prepare_content("application/json")
  luci.http.write_json(e)
end
