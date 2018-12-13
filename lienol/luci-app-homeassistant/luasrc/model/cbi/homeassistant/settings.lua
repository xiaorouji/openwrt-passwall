m = Map("homeassistant",translate("HomeAssistant"))
m:append(Template("homeassistant/status"))

s = m:section(TypedSection,"global",translate("Global Setting"))
s.anonymous = true
s.addremove = false

o = s:option(Flag,"enable",translate("Enable"))
o.rmempty = false

o = s:option(Value, "save_directory", translate("存放路径"), translate("建议插入U盘或硬盘，然后输入路径。例如：/mnt/sda1/homeassistant"))
o.default="/mnt/sda1/homeassistant"
o.rmempty = false

o = s:option(Button, "_download", translate("手动下载"),
	translate("请确保具有足够的空间。<br /><font style='color:red'>第一次运行务必填好存放路径，然后保存应用。再手动下载，否则无法使用！</font>"))
o.template = "homeassistant/download"
o.inputstyle = "apply"
o.btnclick = "downloadClick(this);"
o.id="download_btn"

return m
