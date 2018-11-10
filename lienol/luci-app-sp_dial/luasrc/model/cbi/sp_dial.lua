local fs = require "nixio.fs"
require("luci.tools.webadmin")

n = Map("sp_dial", translate("Special dial"), translate("Dial to the specified beginning of the IP."))

s = n:section(TypedSection, "config")
s.anonymous = true
s.addremove = false

enable=s:option(Flag,"enable", translate("Enable"), translate("Enable special dial."))
enable.rmempty=false

function enable.write(self, section, value)
	if value == "0" then
		os.execute("/etc/init.d/sp_dial stop")
		os.execute("/etc/init.d/sp_dial disable")
	else
		os.execute("/etc/init.d/sp_dial enable")
		os.execute("/etc/init.d/sp_dial start &")
	end
	Flag.write(self, section, value)
end


boot_delay = s:option(Value, "boot_delay", translate("Boot delayed time"))
boot_delay:value("10", "10")
boot_delay:value("10", "10")
boot_delay:value("20", "20")
boot_delay:value("30", "30")
boot_delay.default = "30"
boot_delay.optional = true
boot_delay.rmempty = true

begin = s:option(Value,"begin_a", translate("Special beginning"), translate("Can not be empty, you can fill in the same number."))
begin.rmempty = true

begin = s:option(Value,"begin_b", translate("Special beginning"), translate("Can not be empty, you can fill in the same number."))
begin.rmempty = true

begin = s:option(Value,"begin_c", translate("Special beginning"), translate("Can not be empty, you can fill in the same number."))
begin.rmempty = true

num = s:option(Value, "num", translate("Number of dial-up times"))
num:value("10", "10")
num:value("20", "20")
num:value("30", "30")
num:value("50", "50")
num:value("100", "100")
num.default = "100"
num.optional = true
num.rmempty = true

wait_time = s:option(Value, "wait_time", translate("Dialing interval time"))
wait_time:value("10", "10")
wait_time:value("10", "10")
wait_time:value("20", "20")
wait_time:value("30", "30")
wait_time.default = "20"
wait_time.optional = true
wait_time.rmempty = true

return n