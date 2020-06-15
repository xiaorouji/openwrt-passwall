m = Map("kodexplorer", translate("KodExplorer"), translate("KodExplorer is a fast and efficient private cloud and online document management system that provides secure, controllable, easy-to-use and highly customizable private cloud products for personal websites, enterprise private cloud deployment, network storage, online document management, and online office. With Windows style interface and operation habits, it can be used quickly without adaptation. It supports online preview of hundreds of common file formats and is extensible and easy to customize."))
m:append(Template("kodexplorer/status"))

s = m:section(TypedSection, "global", translate("Global Settings"))
s.anonymous = true
s.addremove = false

o = s:option(Flag, "enable", translate("Enable"))
o.rmempty = false

o = s:option(Value, "port", translate("Nginx Port"))
o.datatype = "port"
o.default = 8081
o.rmempty = false

o = s:option(Flag, "https", translate("HTTPS"))
o.rmempty = false

o = s:option(FileUpload, "certificate", translate("certificate"))
o:depends("https", 1)

o = s:option(FileUpload, "key", translate("key"))
o:depends("https", 1)

o = s:option(Value, "memory_limit", translate("Maximum memory usage"), translate("If your device has a lot of memory, you can increase it."))
o.default = "32M"
o.rmempty = false

o = s:option(Value, "upload_max_filesize", translate("Maximum memory usage for uploading files"))
o.default = "32M"
o.rmempty = false

o = s:option(DynamicList, "open_basedir", translate("Accessible directory"))
o.rmempty = false

o = s:option(Value, "project_directory", translate("Project directory"), translate("It is recommended to insert a usb flash drive or hard disk and enter the path. For example, /mnt/sda1/kodexplorer"))
o.default = "/mnt/sda1/kodexplorer"
o.rmempty = false

s:append(Template("kodexplorer/version"))
return m
