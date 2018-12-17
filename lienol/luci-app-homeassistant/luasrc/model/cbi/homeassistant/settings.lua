m = Map("homeassistant","HomeAssistant","Home Assistant 是一款基于 Python 的智能家居开源系统，支持众多品牌的智能家居设备，可以轻松实现设备的语音控制、自动化等。")
m:append(Template("homeassistant/status"))

s = m:section(TypedSection,"global","基本设置")
s.anonymous = true
s.addremove = false

o = s:option(Flag,"enable",translate("Enable"))
o.rmempty = false

o = s:option(Value,"save_directory","存放路径","建议插入U盘或硬盘，然后输入路径。例如：/mnt/sda1/homeassistant")
o.default="/mnt/sda1/homeassistant"
o.rmempty = false

o = s:option(Button, "_download", "手动下载","请确保具有足够的空间。<br /><font style='color:red'>第一次运行务必填好存放路径，然后保存应用。再手动下载，否则无法使用！</font>")
o.template = "homeassistant/download"
o.inputstyle = "apply"
o.btnclick = "downloadClick(this);"
o.id="download_btn"

return m
