module("luci.controller.sp_dial",package.seeall)

function index()
if not nixio.fs.access("/etc/config/sp_dial")then
  return
end

entry({"admin","network","sp_dial"},cbi("sp_dial"),_("Special dial"),10).dependent=true
entry({"admin","network","sp_dial","status"},call("act_status")).leaf=true
end

function act_status()
  local e={}
  e.sp_dial_status=luci.sys.call("ps | grep server.py |grep -v grep >/dev/null")==0
  luci.http.prepare_content("application/json")
  luci.http.write_json(e)
end
