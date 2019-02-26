module("luci.controller.filebrowser-mini", package.seeall)

function index()

	page = entry({"admin", "nas", "filebrowser-mini"}, template("filebrowser-mini"), _("File Browser Mini"), 1)
	page.i18n = "base"
	page.dependent = true

	page = entry({"admin", "nas", "filebrowser-mini_list"}, call("filebrowser_list"), nil)
	page.leaf = true

	page = entry({"admin", "nas", "filebrowser-mini_open"}, call("filebrowser_open"), nil)
	page.leaf = true

    page = entry({"admin", "nas", "filebrowser-mini_delete"}, call("filebrowser_delete"), nil)
    page.leaf = true

    page = entry({"admin", "nas", "filebrowser-mini_rename"}, call("filebrowser_rename"), nil)
    page.leaf = true

    page = entry({"admin", "nas", "filebrowser-mini_upload"}, call("filebrowser_upload"), nil)
    page.leaf = true

end

function filebrowser_list()
	local rv = { }
	local path = luci.http.formvalue("path")

    rv = scandir(path)	

	if #rv > 0 then
		luci.http.prepare_content("application/json")
		luci.http.write_json(rv)
		return
	end

end

function filebrowser_open(file, filename)
	file = file:gsub("<>", "/")

	local io = require "io"
	local mime = to_mime(filename)

	local download_fpi = io.open(file, "r")
	luci.http.header('Content-Disposition', 'inline; filename="'..filename..'"' )
	luci.http.prepare_content(mime or "application/octet-stream")
	luci.ltn12.pump.all(luci.ltn12.source.file(download_fpi), luci.http.write)
end

function filebrowser_delete()
    local path = luci.http.formvalue("path")
    local isdir = luci.http.formvalue("isdir")
    path = path:gsub("<>", "/")
    path = path:gsub(" ", "\ ")
    if isdir then
        local success = os.execute('rm -r "'..path..'"')
    else
        local success = os.remove(path)
    end
    return success
end

function filebrowser_rename()
    local filepath = luci.http.formvalue("filepath")
    local newpath = luci.http.formvalue("newpath")
    local success = os.execute('mv "'..filepath..'" "'..newpath..'"')
    return success
end

function filebrowser_upload()
    local filecontent = luci.http.formvalue("upload-file")
    local filename = luci.http.formvalue("upload-filename")
    local uploaddir = luci.http.formvalue("upload-dir")
    local filepath = uploaddir..filename
    local url = luci.dispatcher.build_url('admin', 'nas', 'filebrowser')

    local fp
    fp = io.open(filepath, "w")
    fp:write(filecontent)
    fp:close()
    luci.http.redirect(url..'?path='..uploaddir)

    --[[luci.http.setfilehandler(
        function(meta, chunk, eof)
            uci.http.write('open '..filepath)
            if not fp then
                if meta and meta.name == 'upload-file' then
                    --luci.http.write('open file '..filepath)
                    fp = io.open(filepath, "w")
                end
            end
            if fp and chunk then
                --luci.http.write(chunk)
                fp:write(chunk)
            end
            if fp and eof then
                --luci.http.write('close')
                fp:close()
                luci.http.redirect(url..'?path='..uploaddir)
            end
        end
    )]]--
end

function scandir(directory)
    local i, t, popen = 0, {}, io.popen
    
    local pfile = popen("ls -l \""..directory.."\" | egrep '^d' ; ls -lh \""..directory.."\" | egrep -v '^d'")
    for filename in pfile:lines() do
        i = i + 1
        t[i] = filename
    end
    pfile:close()
    return t
end

MIME_TYPES = {
    ["txt"]   = "text/plain";
    ["js"]    = "text/javascript";
    ["css"]   = "text/css";
    ["htm"]   = "text/html";
    ["html"]  = "text/html";
    ["patch"] = "text/x-patch";
    ["c"]     = "text/x-csrc";
    ["h"]     = "text/x-chdr";
    ["o"]     = "text/x-object";
    ["ko"]    = "text/x-object";

    ["bmp"]   = "image/bmp";
    ["gif"]   = "image/gif";
    ["png"]   = "image/png";
    ["jpg"]   = "image/jpeg";
    ["jpeg"]  = "image/jpeg";
    ["svg"]   = "image/svg+xml";

    ["zip"]   = "application/zip";
    ["pdf"]   = "application/pdf";
    ["xml"]   = "application/xml";
    ["xsl"]   = "application/xml";
    ["doc"]   = "application/msword";
    ["ppt"]   = "application/vnd.ms-powerpoint";
    ["xls"]   = "application/vnd.ms-excel";
    ["odt"]   = "application/vnd.oasis.opendocument.text";
    ["odp"]   = "application/vnd.oasis.opendocument.presentation";
    ["pl"]    = "application/x-perl";
    ["sh"]    = "application/x-shellscript";
    ["php"]   = "application/x-php";
    ["deb"]   = "application/x-deb";
    ["iso"]   = "application/x-cd-image";
    ["tgz"]   = "application/x-compressed-tar";

    ["mp3"]   = "audio/mpeg";
    ["ogg"]   = "audio/x-vorbis+ogg";
    ["wav"]   = "audio/x-wav";

    ["mpg"]   = "video/mpeg";
    ["mpeg"]  = "video/mpeg";
    ["avi"]   = "video/x-msvideo";
}

function to_mime(filename)
	if type(filename) == "string" then
		local ext = filename:match("[^%.]+$")

		if ext and MIME_TYPES[ext:lower()] then
			return MIME_TYPES[ext:lower()]
		end
	end

	return "application/octet-stream"
end