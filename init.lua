-----------------------------------------------------------------------------
-- Belial web waf
-- Author: 逆雪寒
-- Copyright (c) 2013 半夜三更
-----------------------------------------------------------------------------
local Conf = require("config")

_Object = {
	__DEBUG__ = true,
	_Conf = {
		whiteListFileName = Conf.allowAccessPostFilePath,
		belialFileName = Conf.belialFileLogPath,
		rejectList = Conf.rejectPostLogPath,
		ipDenyList = Conf.denyIPAccess
	},
	Conf = Conf,
	_ListState = {
		down = 0,
		valid = 1
	},
	_ErrorLevel = {
		error = "error",
		notice = "notice"
	}
}

function _Object:BelialFactory(o)
	 setmetatable(o,{__index=self})
	 return o
end

function _Object:saveFile(data,target)	
	if Conf.toLog == "On" then
		local fd = io.open(target,"ab")
		if fd == nil then return end
		fd:write(data .. "\n")
		fd:flush()
		fd:close()
	end
end


function _Object:toLog(msg,level)
	self:saveFile("["..((not level and "notice") or level).."]::"..msg,self._Conf.belialFileName)

end

--写入白名单
function _Object:toWhiteFile(data)
	self:saveFile(data,self._Conf.whiteListFileName)
end


function _Object:inTable(_table,var)
	if type(_table) ~= "table" then return false end
	
	for _,v in pairs(_table) do 
		if v == var then 
			return true  
		end 
	end
	return false
end

function _Object:explode (_str,seperator)
	local pos, arr = 0, {}
		for st, sp in function() return string.find( _str, seperator, pos, true ) end do
			table.insert( arr,string.sub( _str, pos, st-1 ))
			pos = sp + 1
		end
	table.insert( arr, string.sub( _str, pos ) )
	return arr
end

function _Object:split(line)
	local _tokens = {}
	for token in string.gmatch(line, "[^%s]+") do
	   table.insert(_tokens,token)
	end
	return _tokens[1],_tokens[2],_tokens[3]
end

--调试
function _Object:__debugOutput(msg)
	if self.__DEBUG__ then self:toLog(msg) end
end

function _Object:__debugDisplay(msg)
	if self.__DEBUG__ then 
		ngx.header.content_type = "text/html"
		ngx.say(msg)
		ngx.exit(ngx.HTTP_OK)
	end
end

Belial = _Object:BelialFactory({
	__Belial_version__ = "0.8",
	_baseRegexFilterRule = {
		get = "'|(and|or)\\b.+?(>|<|=|\\bin|\\blike)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)|\\.\\.\\/|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
		post = "base64_decode|\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT.+?INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE).+?(TABLE|DATABASE)|\\.\\/|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
		cookie = "\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)",
		ngxPathInfoFix = "\\.[^php|com]+\\/.*php"
	}
})

function Belial:new()
	return self
end

--收集白名单
function Belial:toWhiteList(data)
	self:toWhiteFile(data)
end

function Belial:errorPage(error)
	local _tpl = string.format([[<html>
			<head><title>Belial web waf/%s</title></head>
			<body bgcolor="white">
			<center><h1>%s</h1></center>
			<hr><center>belial/%s</center>
			</body>
			</html>
	]],self.__Belial_version__,error,self.__Belial_version__)
	
	--自定义攻击界面
	local attachPageHtml = self:attackHtmlPage()
	if attachPageHtml then
		_tpl =  attachPageHtml
	end

	ngx.header.content_type = "text/html"
	ngx.say(_tpl)

	ngx.exit(ngx.HTTP_OK)
end

--自定意攻击拦截页面
function Belial:attackHtmlPage()
	
	if self.Conf.attackHtmlPageName ~= "" then
		local fd = io.open(self.Conf.attackHtmlPageName,"rb")
		if fd == nil then
			return
		end
		return fd:read("*a")
	else
		return nil
	end
	
end


function Belial:getClientIp()
	if not self.Conf.isBackend then
		if ngx.var.remote_addr ~= nil then
			IP  = ngx.var.remote_addr
		else
			IP  = "uknow"
		end
	else
		IP = ngx.req.get_headers()["X-Real-IP"]
		if IP == nil then
			IP  = ngx.var.remote_addr
		end
		if IP == nil then
			IP  = "uknow"
		end
	end
	return IP
end


function Belial:start(safeModule)
	for _,m in pairs(safeModule) do m() end
end

-- ngx.share.dict

NgxShareDict = _Object:BelialFactory({belialBaiDict=nil})

function NgxShareDict:new()
	
	self.belialBaiDict = ngx.shared.belial
	if not self.belialBaiDict then
		return false
	end
	return self
end

function NgxShareDict:set(line,ac)
	local succ, err, forcible = self.belialBaiDict:add(line,ac)
	--内存不足提示
	if not succ then self:toLog("lua_shared_dict belial was full",self._ErrorLevel.error) end
	if forcible then self:toLog("lua_shared_dict belial will be full",self._ErrorLevel.notice)  end
end

function NgxShareDict:get(k)
	return self.belialBaiDict:get(k)
end

function NgxShareDict:flush()
	self.belialBaiDict:flush_all() 
end

--加载白名单到shared

function NgxShareDict:loadWhiteListToShareDict()
	if self.belialBaiDict == nil then
		self:toLog("lua_shared_dict belial is not defined in nginx.conf",self._ErrorLevel.notice)
	end
	
	self:flush()
	local fd = io.open(self._Conf.whiteListFileName,"rb")
	if fd == nil then
		self:toLog(self._Conf.whiteListFileName .. " is not found",self._ErrorLevel.error)
		return
	end
	
	for line in fd:lines() do
		local rule = line
		local ac = self._ListState["valid"]
		
		local prefix = string.sub(rule,1,1)

		if prefix == "#" then --被注释
			rule = string.sub(rule,2)
			ac = self._ListState["down"]
		end
		
		if rule then
			rule = self.Conf.webProjectRootDirectory ..rule --完整白名单路径
			self:set(rule,ac)
		end
	end
	fd:close()
end

denyIpAccessDict = _Object:BelialFactory({
	denyIPlist = {}
})

function denyIpAccessDict:set(k)
	if not self:inTable(self.denyIPlist,k) then
		local fd = io.open(self.Conf.denyIPAccess,"wb")
		if fd == nil then
			self:toLog(self.Conf.denyIPAccess .. " is not found",self._ErrorLevel.error)
			return
		end
		fd:write(k)
		fd:close()
		table.insert(self.denyIPlist,k)
	end
end

function denyIpAccessDict:new()
	return self
end

function denyIpAccessDict:get(k)
	return self:inTable(self.denyIPlist,k)
end

function denyIpAccessDict:flush()
	for _,v in pairs(self.denyIPlist) do tab[k]=nil end
end

function denyIpAccessDict:print()
	self:__debugOutput(table.concat(self.denyIPlist," "),"error")	
end

function denyIpAccessDict:load()
	if not self.Conf.denyIPAccess then return end
	local denyIpAccessFileName = self._Conf.ipDenyList
	
	local fd = io.open(denyIpAccessFileName,"rb")
	if fd == nil then
		self:toLog(denyIpAccessFileName .. " is not found",self._ErrorLevel.error)
		return
	end
	
	for ip in fd:lines() do
		if ip and not self:inTable(self.denyIPlist,ip) then
			self:set(ip)
		end
	end
	
	fd:close()
end

--自动防护模式
NgxAutoDenyDict = _Object:BelialFactory({
		belialAudoDenyDict=nil,
		__exptime__ = 86400 --exptime
})

function NgxAutoDenyDict:new()
	self.belialAudoDenyDict = ngx.shared.belialAutoDeny
	if self.belialAudoDenyDict == nil then
		self:toLog("belialAutoDeny belial is not defined in nginx.conf",self._ErrorLevel.notice)
		return false
	end
	self.__exptime__ = self.Conf.autoDenyRuleExptimeSecond
	return self
end

function NgxAutoDenyDict:set(line,ac)
	local succ, err, forcible = self.belialAudoDenyDict:add(line,ac,self.__exptime__)
	--内存不足提示
	if not succ then self:toLog("belialAudoDenyDict belial was full",self._ErrorLevel.error) end
	if forcible then self:toLog("belialAudoDenyDict belial will be full",self._ErrorLevel.notice)  end
end

function NgxAutoDenyDict:get(k)
	return self.belialAudoDenyDict:get(k)
end

function NgxAutoDenyDict:replace(k,v)
	self.belialAudoDenyDict:replace(k,v,self.__exptime__)
end

function NgxAutoDenyDict:flush()
	self.belialAudoDenyDict:flush_all() 
end

function NgxAutoDenyDict:format(times,attackAmount,requestAmountMilliseconds)
	return times .. " " ..attackAmount .. " " ..requestAmountMilliseconds
end



BlShareDict =  NgxShareDict:new()
if BlShareDict then
	BlShareDict:loadWhiteListToShareDict()
end

IpAccessDict = denyIpAccessDict:new()
IpAccessDict:load()

audoDenyDict = NgxAutoDenyDict:new()
if audoDenyDict then
	audoDenyDict:flush()
end





