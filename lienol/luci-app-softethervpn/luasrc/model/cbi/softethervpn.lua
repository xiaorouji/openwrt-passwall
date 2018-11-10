local s=require"luci.sys"
local m,s,o
m=Map("softethervpn",translate("SoftEther VPN"))
m.description = translate("SoftEther VPN is an open source, cross-platform, multi-protocol virtual private network solution developed by university of tsukuba graduate student Daiyuu Nobori for master's thesis. <br>can easily set up OpenVPN, IPsec, L2TP, ms-sstp, L2TPv3 and EtherIP servers on the router using the console.")
m.template="softethervpn/index"
--local pid = luci.util.exec("/usr/bin/pgrep vpnserver")
--if pid == "" then
--start = s:option(Button, "_start", translate("Start"),translate("<span style='color:red'>保存并应用并不会执行脚本，请自行启动服务</span>"))
--start.inputstyle = "apply"
--function start.write(self, section)
--luci.util.exec("/etc/init.d/softethervpn start")
--luci.http.redirect(luci.dispatcher.build_url("admin", "vpn", "softethervpn"))
--end
--else
--stop = s:option(Button, "_stop", translate("Stop"),translate("<span style='color:red'>保存并应用并不会执行脚本，请自行关闭服务</span>"))
--stop.inputstyle = "reset"
--function stop.write(self, section)
--luci.util.exec("/etc/init.d/softethervpn stop")
--luci.http.redirect(luci.dispatcher.build_url("admin", "vpn", "softethervpn"))
--end
--end
s=m:section(TypedSection,"softether")
s.anonymous=true
o=s:option(DummyValue,"softethervpn_status",translate("Current Condition"))
o.template="softethervpn/status"
o.value=translate("Collecting data...")
o=s:option(Flag,"enable",translate("Enabled"))
o.rmempty=false
o=s:option(Flag,"l2tp",translate("Open L2TP/IPSec firewall"))
o.rmempty=false
o=s:option(Flag,"sstp",translate("Open the MS-SSTP firewall"))
o.rmempty=false
o=s:option(Flag,"openvpn",translate("Open the OpenVPN firewall"))
o.rmempty=false
o=s:option(DummyValue,"moreinfo",translate("<strong>控制台下载：<a onclick=\"window.open('http://www.softether-download.com/files/softether/v4.22-9634-beta-2016.11.27-tree/Windows/SoftEther_VPN_Server_and_VPN_Bridge/softether-vpnserver_vpnbridge-v4.22-9634-beta-2016.11.27-windows-x86_x64-intel.exe')\"><br/>Windows-x86_x64-intel.exe</a><a  onclick=\"window.open('http://www.softether-download.com/files/softether/v4.21-9613-beta-2016.04.24-tree/Mac_OS_X/Admin_Tools/VPN_Server_Manager_Package/softether-vpnserver_manager-v4.21-9613-beta-2016.04.24-macos-x86-32bit.pkg')\"><br/>macos-x86-32bit.pkg</a></strong>"))
return m
