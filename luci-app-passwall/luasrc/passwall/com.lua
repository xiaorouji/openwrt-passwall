local _M = {}

local function gh_release_url(self)
	return "https://api.github.com/repos/" .. self.repo .. "/releases/latest"
end

local function gh_pre_release_url(self)
	return "https://api.github.com/repos/" .. self.repo .. "/releases?per_page=1"
end

_M.hysteria = {
	name = "Hysteria",
	repo = "HyNetwork/hysteria",
	get_url = gh_release_url,
	cmd_version = "version | awk '/^Version:/ {print $2}'",
	remote_version_str_replace = "app/",
	zipped = false,
	default_path = "/usr/bin/hysteria",
	match_fmt_str = "linux%%-%s$",
	file_tree = {
		armv6 = "arm",
		armv7 = "arm"
	}
}

_M.singbox = {
	name = "Sing-Box",
	repo = "SagerNet/sing-box",
	get_url = gh_pre_release_url,
	cmd_version = "version | awk '{print $3}' | sed -n 1P",
	zipped = true,
	zipped_suffix = "tar.gz",
	default_path = "/usr/bin/sing-box",
	match_fmt_str = "linux%%-%s",
	file_tree = {
		x86_64 = "amd64"
	}
}

_M.xray = {
	name = "Xray",
	repo = "XTLS/Xray-core",
	get_url = gh_pre_release_url,
	cmd_version = "version | awk '{print $2}' | sed -n 1P",
	zipped = true,
	default_path = "/usr/bin/xray",
	match_fmt_str = "linux%%-%s",
	file_tree = {
		x86_64 = "64",
		x86    = "32",
		mips   = "mips32",
		mipsel = "mips32le"
	}
}

_M["chinadns-ng"] = {
	name = "ChinaDNS-NG",
	repo = "zfl9/chinadns-ng",
	get_url = gh_release_url,
	cmd_version = "-V | awk '{print $2}'",
	zipped = false,
	default_path = "/usr/bin/chinadns-ng",
	match_fmt_str = "%s$",
	file_tree = {
		x86_64  = "@x86_64@",
		x86     = "@i686@",
		mips    = "mips-linux-musl@mips32@",
		mipsel  = "mipsel-linux-musl@mips32@",
		aarch64 = "aarch64-linux-musl@generic+v8a",
		armv5   = "arm-linux-musleabi@generic+v5te",
		armv6   = "arm-linux-musleabi@generic+v6t2",
		armv7   = "arm-linux-musleabihf@generic+v7a",
		armv8   = "aarch64-linux-musl@generic+v8a"
	}
}

return _M
