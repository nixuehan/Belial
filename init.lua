-----------------------------------------------------------------------------
-- Belial web waf
-- Author: 逆雪寒
-- Copyright (c) 2013 半夜三更
-----------------------------------------------------------------------------
require("config")

__Belial_version__ = "0.8.0"
__DEBUG__ = true
_baseRegexFilterRule = {
	get = "'|(and|or)\\b.+?(>|<|=|\\bin|\\blike)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)|\\.\\/|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
	post = "base64_decode|\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT.+?INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE).+?(TABLE|DATABASE)|\\.\\/|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
	cookie = "\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION\\b.+?SELECT|UPDATE\\b.+?)SET|INSERT\\b.+?INTO.+?VALUES|(SELECT|DELETE)\\b.+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\b.+?(TABLE|DATABASE)",
	cgiPath = "\\.[^php|com]+\\/.*php"
}


function getClientIp()
	IP = ngx.req.get_headers()["X_FORWARDED_FOR"]
	if IP == nil then
		IP = ngx.req.get_headers()["X-Real-IP"]
	end
	if IP == nil then
		IP  = ngx.var.remote_addr
	end
	if IP == nil then
		IP  = "uknow"
	end
	return IP
end



_Conf = {
	whiteListFileName = Conf.rootDirectory .. "allow.belial",
	belialFileName = Conf.rootDirectory .. Conf.logDirectory .. "log.belial",
	rejectList = Conf.rootDirectory .. Conf.logDirectory .. "reject.belial"
}

_WhiteListState = {
	down = 0,
	valid = 1
}

function inTable(_table,var)
	for _,v in pairs(_table) do
		if v == var then return true  end
	end
	return false
end

_client_ip_ = ""
_self_url_ = ""
-- log template
function clientInfoLog()
	return " "..getClientIp().." "
			.." ["..ngx.localtime().."] "
			..ngx.status.." "
			..ngx.var.http_user_agent
end

function errorPage(error)
	local _tpl = string.format([[<html>
			<head><title>Belial web waf/%s</title></head>
			<body bgcolor="white">
			<center><h1>%s</h1></center>
			<hr><center>belial/%s</center>
			</body>
			</html>
	]],__Belial_version__,error,__Belial_version__)
	
	--自定义攻击界面
	local attachPageHtml = attackHtmlPage()
	if attachPageHtml then
		_tpl =  attachPageHtml
	end

	ngx.header.content_type = "text/html"
	ngx.say(_tpl)

	ngx.exit(ngx.HTTP_OK)
end

function __debugOutput(msg)
	if __DEBUG__ then Log:set({toBelialLog = msg,clientInfo = false}) end
end

--自定意攻击拦截页面
function attackHtmlPage()
	
	if Conf.attackHtmlPageName ~= "" then
		local fd = io.open(Conf.attackHtmlPageName,"rb")
		if fd == nil then
			return
		end
		return fd:read("*a")
	else
		return nil
	end
	
end

--加载白名单到shared

function loadWhiteListToShareDict()
	
	if belialBaiDict == nil then
		Log:set({toBelialLog = "lua_shared_dict belial is not defined in nginx.conf",clientInfo = false})
	end
	
	
	local fd = io.open(_Conf.whiteListFileName,"rb")
	if fd == nil then
		Log:set({toBelialLog = _Conf.whiteListFileName .. " is not found",clientInfo = false})
		return
	end
	
	for line in fd:lines() do
		local rule = line
		local ac = _WhiteListState["valid"]
		
		local prefix = string.sub(rule,1,1)

		if prefix == "#" then --被注释
			rule = string.sub(rule,2)
			ac = _WhiteListState["down"]
		end

		if rule then
			
			rule = Conf.webProjectRootDirectory ..rule --完整白名单路径
			ngxShareDict:set(rule,ac)
		end
	end
	fd:close()
end





--Log class
--
Log = {
	target = _Conf.belialFileName
}


--添加白名单
function Log:toWhiteList(data)
	self.target = _Conf.whiteListFileName
	self:_write(data)
end

--纪录日志
function Log:set(options) --errorPageContent,toBelialLog,tags
	if not options.tags then  options.tags = "notice"  end
	if Conf.toLog == "On" and options.toBelialLog then Log:toBelial(options.toBelialLog,options.tags,options.clientInfo) end
	if options.errorPageContent then errorPage(options.errorPageContent) end
end


function Log:toBelial(data,tags,clientInfo)
	if clientInfo ~= false then data = data .. clientInfoLog() end
	
	local fd = io.open(self.target,"ab")
	if fd == nil then
		return
	end
	fd:write("["..((not tags and "notice") or tags).."]::" .. data .. "\n")
	fd:flush()
	fd:close()
end

function Log:_toNginxError(data)
	ngx.log(ngx.ERR,"[Belial]" .. data)
end

-- ngx.share.dict
ngxShareDict = {}

function ngxShareDict:set(line,ac)
	local succ, err, forcible = belialBaiDict:set(line,ac)
	--内存不足提示
	if not succ then Log:set({toBelialLog = "lua_shared_dict belial was full",tags = "error",clientInfo = false}) end
	if forcible then  Log:set({toBelialLog = "lua_shared_dict belial will be full",clientInfo = false})  end
end

function ngxShareDict:get(k)
	return belialBaiDict:get(k)
end


belialBaiDict = ngx.shared.belial
if Conf.whiteModule == "On" then
	belialBaiDict:flush_all() --清空
	loadWhiteListToShareDict()
end