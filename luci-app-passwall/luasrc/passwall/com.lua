local _M = {}

local function gh_release_url(repo)
    return "https://api.github.com/repos/" .. repo .. "/releases/latest"
end

local function gh_pre_release_url(repo)
    return "https://api.github.com/repos/" .. repo .. "/releases?per_page=1"
end

_M.brook = {
    name = "Brook",
    api_url = gh_release_url("txthinking/brook"),
    cmd_version = "-v | awk '{print $3}'",
    zipped = false,
    default_path = "/usr/bin/brook",
    get_match_name = function(file_tree, sub_version)
        return "linux_" .. file_tree .. sub_version
    end
}
_M.hysteria = {
    name = "Hysteria",
    api_url = gh_release_url("HyNetwork/hysteria"),
    cmd_version = "-v | awk '{print $3}'",
    zipped = false,
    default_path = "/usr/bin/hysteria",
    get_match_name = function(file_tree, sub_version)
        if file_tree=="arm" and sub_version=="5" then file_tree = "armv5" end
        return "linux%-" .. file_tree .. "$"
    end
}
_M["trojan-go"] = {
    name = "Trojan-Go",
    api_url = gh_release_url("p4gefau1t/trojan-go"),
    cmd_version = "-version | awk '{print $2}' | sed -n 1P",
    zipped = true,
    default_path = "/usr/bin/trojan-go",
    get_match_name = function(file_tree, sub_version)
        if file_tree == "mips" then file_tree = "mips%-hardfloat"
        elseif file_tree == "mipsle" then file_tree = "mipsle%-hardfloat"
        elseif file_tree == "arm64" then file_tree = "armv8"
        elseif sub_version and sub_version:match("^[5-8]$") then
            file_tree = file_tree .. "v" .. sub_version
        end
        return "linux%-" .. file_tree .. "%.zip"
    end
}
_M.v2ray = {
    name = "V2ray",
    api_url = gh_pre_release_url("v2fly/v2ray-core"),
    cmd_version = "version | awk '{print $2}' | sed -n 1P",
    zipped = true,
    default_path = "/usr/bin/v2ray",
    get_match_name = function(file_tree, sub_version)
        if file_tree == "amd64" then file_tree = "64"
        elseif file_tree == "386" then file_tree = "32"
        elseif file_tree == "mipsle" then file_tree = "mips32le"
        elseif file_tree == "mips" then file_tree = "mips32"
        elseif file_tree == "arm" then file_tree = "arm32" end
        return "linux%-" .. file_tree .. (sub_version ~= "" and ".+" .. sub_version or "")
    end
}
_M.xray = {
    name = "Xray",
    api_url = gh_pre_release_url("XTLS/Xray-core"),
    cmd_version = _M.v2ray.cmd_version,
    zipped = true,
    default_path = "/usr/bin/xray",
    get_match_name = _M.v2ray.get_match_name
}
_M["chinadns-ng"] = {
    name = "ChinaDNS-NG",
    api_url = gh_pre_release_url("zfl9/chinadns-ng"),
    cmd_version = "-V | awk '{print $2}'",
    zipped = no,
    default_path = "/usr/bin/chinadns-ng",
    get_match_name = function(file_tree, sub_version)
        if file_tree == "amd64" then file_tree = "x86_64"
        elseif file_tree == "386" then file_tree = "i686"
        elseif file_tree == "mipsle" then file_tree = "mipsel"
        elseif file_tree == "arm64" then file_tree = "aarch64"
        elseif file_tree == "arm" then
            file_tree = "arm%-eabi"
            if sub_version and sub_version:match("^[6-7]$") then
				file_tree = "arm%-eabihf"
			end
        end
        return file_tree .. "$"
    end
}

return _M