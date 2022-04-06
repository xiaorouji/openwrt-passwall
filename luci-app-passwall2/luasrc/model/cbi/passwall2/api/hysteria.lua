module("luci.model.cbi.passwall2.api.hysteria", package.seeall)
local api = require "luci.model.cbi.passwall2.api.api"
local fs = api.fs
local sys = api.sys
local util = api.util
local i18n = api.i18n

local pre_release_url = "https://api.github.com/repos/HyNetwork/hysteria/releases?per_page=1"
local release_url = "https://api.github.com/repos/HyNetwork/hysteria/releases/latest"
local api_url = release_url
local app_path = api.get_hysteria_path() or ""

function check_path()
    if app_path == "" then
        return {
            code = 1,
            error = i18n.translatef("You did not fill in the %s path. Please save and apply then update manually.", "hysteria")
        }
    end
    return {
        code = 0
    }
end

function to_check(arch)
    local result = check_path()
    if result.code ~= 0 then
        return result
    end

    if not arch or arch == "" then arch = api.auto_get_arch() end

    local file_tree, sub_version = api.get_file_info(arch)

    if file_tree == "" then
        return {
            code = 1,
            error = i18n.translate("Can't determine ARCH, or ARCH not supported.")
        }
    end

    return api.common_to_check(api_url, api.get_hysteria_version(), "linux%-" .. file_tree .. sub_version)
end

function to_download(url, size)
    local result = check_path()
    if result.code ~= 0 then
        return result
    end

    if not url or url == "" then
        return {code = 1, error = i18n.translate("Download url is required.")}
    end

    sys.call("/bin/rm -f /tmp/hysteria_download.*")

    local tmp_file = util.trim(util.exec("mktemp -u -t hysteria_download.XXXXXX"))

    if size then
        local kb1 = api.get_free_space("/tmp")
        if tonumber(size) > tonumber(kb1) then
            return {code = 1, error = i18n.translatef("%s not enough space.", "/tmp")}
        end
    end

    result = api.exec(api.curl, {api._unpack(api.curl_args), "-o", tmp_file, url}, nil, api.command_timeout) == 0

    if not result then
        api.exec("/bin/rm", {"-f", tmp_file})
        return {
            code = 1,
            error = i18n.translatef("File download failed or timed out: %s", url)
        }
    end

    return {code = 0, file = tmp_file}
end

function to_move(file)
    local result = check_path()
    if result.code ~= 0 then
        return result
    end

    if not file or file == "" or not fs.access(file) then
        sys.call("/bin/rm -rf /tmp/hysteria_download.*")
        return {code = 1, error = i18n.translate("Client file is required.")}
    end

    local new_version = api.get_hysteria_version(file)
    if new_version == "" then
        sys.call("/bin/rm -rf /tmp/hysteria_download.*")
        return {
            code = 1,
            error = i18n.translate("The client file is not suitable for current device.")
        }
    end

    local flag = sys.call('pgrep -af "passwall2/.*hysteria" >/dev/null')
    if flag == 0 then
        sys.call("/etc/init.d/passwall2 stop")
    end

    local old_app_size = 0
    if fs.access(app_path) then
        old_app_size = api.get_file_space(app_path)
    end
    local new_app_size = api.get_file_space(file)
    local final_dir = api.get_final_dir(app_path)
    local final_dir_free_size = api.get_free_space(final_dir)
    if final_dir_free_size > 0 then
        final_dir_free_size = final_dir_free_size + old_app_size
        if new_app_size > final_dir_free_size then
            sys.call("/bin/rm -rf /tmp/hysteria_download.*")
            return {code = 1, error = i18n.translatef("%s not enough space.", final_dir)}
        end
    end

    result = api.exec("/bin/mv", {"-f", file, app_path}, nil, api.command_timeout) == 0

    sys.call("/bin/rm -rf /tmp/hysteria_download.*")
    if flag == 0 then
        sys.call("/etc/init.d/passwall2 restart >/dev/null 2>&1 &")
    end

    if not result or not fs.access(app_path) then
        return {
            code = 1,
            error = i18n.translatef("Can't move new file to path: %s", app_path)
        }
    end

    return {code = 0}
end
