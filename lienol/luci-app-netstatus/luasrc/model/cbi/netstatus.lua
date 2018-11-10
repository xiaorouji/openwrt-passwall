local fs = require "nixio.fs"
require("luci.tools.webadmin")

l = Map("netstatus", translate("Network status monitor and restart."))

s = l:section(TypedSection, "netstatus", translate("config"), translate("Monitor network status,and restart network when offline."))
s.anonymous = true 
s.addremove = false

enable = s:option(Flag, "enable", translate("Enable"), translate("Enable or Disable network status monitor."))
enable.default = false
enable.optional = false
enable.rmempty = false

function enable.write(self, section, value)
	if value == "0" then
		os.execute("/etc/init.d/netstatus disable")
		os.execute("/etc/init.d/netstatus stop")
	else
		os.execute("/etc/init.d/netstatus enable")
	end
	Flag.write(self, section, value)
end


o = s:option(Value, "boot_time", translate("Boot_time"), translate("Delayed time while booting(seconds)."))
o.default = 30
o:value("30", "30")
o:value("50", "50")
o:value("80", "80")
o:value("120", "120")

o.default = "50"
o.optional = true
o.rmempty = false


check_interval = s:option(Value, "check_interval", translate("Check_interval"),translate("Check interval for network status check."))
check_interval:value("20", "20")
check_interval:value("30", "30")
check_interval:value("50", "50")
check_interval:value("80", "80")
check_interval:value("120", "120")
check_interval.default = "50"
check_interval.optional = true
check_interval.rmempty = true

return l