module("luci.controller.pppoe-relay",package.seeall)
function index()
	if not nixio.fs.access("/etc/config/pppoe-relay")then
	return
end

entry({"admin","services","pppoe-relay"},cbi("pppoe-relay"),_("PPPoE Relay"),2).dependent=true
end