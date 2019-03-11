local ucursor = require "luci.model.uci".cursor()
local json = require "luci.jsonc"
local json_str = arg[1]
local result_str = arg[2]

local object = json.parse(json_str)
local v = object.v
local host = object.host
local ps = object.ps
local add = object.add
local port = object.port
local id = object.id
local aid = object.aid
local net = object.net
local type = object.type
local path = object.path
local tls = object.tls

local result = "v = "..v..
"\n".."host = "..host..
"\n".."ps = "..ps..
"\n".."add = "..add..
"\n".."port = "..port..
"\n".."id = "..id..
"\n".."aid = "..aid..
"\n".."net = "..net..
"\n".."type = "..type..
"\n".."path = "..path..
"\n".."tls = "..tls
print(result)