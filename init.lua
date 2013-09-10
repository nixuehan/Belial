-----------------------------------------------------------------------------
-- Belial web waf
-- Author: 逆雪寒
-- Copyright (c) 2013 半夜三更
-----------------------------------------------------------------------------
local Conf = require("config")
local result = require("rule")

local regularRule,ccUrlList = result["regularRule"],result["ccUrlList"]

local optionIsOn = function (options) return options == "On" and true or false end

_Object = {
	__DEBUG__ = true,
	_Conf = {
		whiteListFileName = Conf.allowAccessPostFilePath,
		belialFileName = Conf.belialFileLogPath,
		rejectList = Conf.rejectPostLogPath,
		ipDenyList = Conf.denyIPAccess,
		ccMatch = optionIsOn(Conf.ccMatch),
		ccDebug = optionIsOn(Conf.ccDebug),
		autoDenyIpModule = optionIsOn(Conf.autoDenyIpModule),
		postMatch = optionIsOn(Conf.postMatch),
		cookieMatch = optionIsOn(Conf.cookieMatch),
		ngxPathInfoFixModule = optionIsOn(Conf.ngxPathInfoFixModule),
		whiteModule = optionIsOn(Conf.whiteModule),
		getTogether = optionIsOn(Conf.getTogether),
		toLog = optionIsOn(Conf.toLog),
		ccGlobalLog = optionIsOn(Conf.ccGlobalLog)
	},
	Conf = Conf,
	CcRule = ccUrlList, --cc list
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
	if self._Conf.toLog then
		local fd = io.open(target,"ab")
		if fd == nil then return end
		fd:write(data .. "\n")
		fd:flush()
		fd:close()
	end
end

function _Object:cclog(msg)
	self:saveFile(msg,self.Conf.ccDebugLogPath)
end

function _Object:ccGlobalLog(msg)
	self:saveFile(msg,self.Conf.ccGloablLogPath)
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

function _Object:_False(var)
	if var == 0 or var == "" or var == nil or var == false then
		return true
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
	__Belial_version__ = "1.0",
	_baseRegexFilterRule = ""
})

function Belial:new()
	self._baseRegexFilterRule = regularRule[self.Conf.regularRule] and regularRule[self.Conf.regularRule] or regularRule["default"]
	return self
end

--收集白名单
function Belial:toWhiteList(data)
	self:toWhiteFile(data)
end

function Belial:errorPage(error)
	local _tpl = string.format([[<html>
			<head><title>Belial waf/%s</title></head>
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
	IP = ngx.req.get_headers()["X-Real-IP"]
	if IP == nil then
		IP  = ngx.var.remote_addr
	end
	if IP == nil then
		IP  = "uknow"
	end
	return IP
end


function Belial:start(safeModule)
	for _,m in pairs(safeModule) do m() end
end

-- ngx.share.dict

NgxShareDict = _Object:BelialFactory({belialBaiDict=nil})

function NgxShareDict:new()
	
	self.belialBaiDict = ngx.shared.belial_post_allow
	if not self.belialBaiDict then
		if self._Conf.whiteModule then self:toLog("belial_post_allow is not defined in nginx.conf",self._ErrorLevel.notice) end
		return false
	end
	self:loadWhiteListToShareDict()
	return self
end

function NgxShareDict:set(line,ac)
	local succ, err, forcible = self.belialBaiDict:add(line,ac)
	--内存不足提示
	if not succ then self:toLog("belial_post_allow belial error:" .. err,self._ErrorLevel.notice) end
	if forcible then self:toLog("belial_post_allow belial will be full",self._ErrorLevel.notice)  end
end

function NgxShareDict:get(k)
	return self.belialBaiDict:get(k)
end

function NgxShareDict:flush()
	self.belialBaiDict:flush_all() 
end

--加载白名单到shared

function NgxShareDict:loadWhiteListToShareDict()
	if self.belialBaiDict == nil then return end
	
	self:flush()
	local fd = io.open(self._Conf.whiteListFileName,"rb")
	if fd == nil then
		self:toLog(self._Conf.whiteListFileName .. " is not found",self._ErrorLevel.notice)
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
		table.insert(self.denyIPlist,k)
	end
end

function denyIpAccessDict:new()
	self:load()
	return self
end

function denyIpAccessDict:get(k)
	return self:inTable(self.denyIPlist,k)
end

function denyIpAccessDict:flush()
	for _,v in pairs(self.denyIPlist) do tab[k]=nil end
end

function denyIpAccessDict:print()
	self:__debugOutput(table.concat(self.denyIPlist," "),"notice")	
end

function denyIpAccessDict:load()
	if not self.Conf.denyIPAccess then return end
	local denyIpAccessFileName = self._Conf.ipDenyList
	
	if  self:_False(denyIpAccessFileName) then return end
	
	local fd = io.open(denyIpAccessFileName,"rb")
	if fd == nil then
		self:toLog(denyIpAccessFileName .. " is not found",self._ErrorLevel.notice)
		return
	end
	
	for ip in fd:lines() do
		if ip then
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
	self.belialAudoDenyDict = ngx.shared.belial_auto_deny
	if self.belialAudoDenyDict == nil then
		if self._Conf.autoDenyIpModule then self:toLog("belial_auto_deny is not defined in nginx.conf",self._ErrorLevel.notice) end
		return false
	end
	self.__exptime__ = self.Conf.autoDenyRuleExptimeSecond
	self:flush()
	return self
end

function NgxAutoDenyDict:set(line,ac)
	local succ, err, forcible = self.belialAudoDenyDict:add(line,ac,self.__exptime__)
	--内存不足提示
	if not succ then self:toLog("belial_auto_deny belial error:" .. err,self._ErrorLevel.notice) end
	if forcible then self:toLog("belial_auto_deny belial will be full",self._ErrorLevel.notice)  end
end

function NgxAutoDenyDict:get(k)
	return self.belialAudoDenyDict:get(k)
end

function NgxAutoDenyDict:delete(k)
	self.belialAudoDenyDict:delete(k)
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


--cc防御存储
NgxCCDict = _Object:BelialFactory({
		belialCCDict=nil,
		__exptime__ = 86400 --exptime
})

function NgxCCDict:new()
	self.belialCCDict = ngx.shared.belial_cc_deny
	if self.belialCCDict == nil then
		if self._Conf.ccMatch then self:toLog("belial_cc_deny is not defined in nginx.conf",self._ErrorLevel.notice) end
		return false
	end
	self.__exptime__ = self.Conf.ccDenyTagExptimeSecond
	self:flush()
	return self
end

function NgxCCDict:set(line,ac)
	local succ, err, forcible = self.belialCCDict:add(line,ac,self.__exptime__)
	--内存不足提示
	if not succ then self:toLog("belial_cc_deny  error:" .. err,self._ErrorLevel.notice) end
	if forcible then self:toLog("belial_cc_deny  will be full",self._ErrorLevel.notice)  end
end

function NgxCCDict:get(k)
	return self.belialCCDict:get(k)
end

function NgxCCDict:replace(k,v)
	self.belialCCDict:replace(k,v,self.__exptime__)
end

function NgxCCDict:incr(k)
	self.belialCCDict:incr(k,1)
end

function NgxCCDict:delete(k)
	self.belialCCDict:delete(k)
end

function NgxCCDict:flush()
	self.belialCCDict:flush_all() 
end


--cc防御存储
NgxCCGlobalDict = _Object:BelialFactory({
		belialCCGlobalDict=nil,
		__exptime__ = 86400 --exptime
})

function NgxCCGlobalDict:new()
	self.belialCCGlobalDict = ngx.shared.belial_cc_global
	if self.belialCCGlobalDict == nil then
		if self._Conf.ccGlobalLog then self:toLog("belial_cc_global is not defined in nginx.conf",self._ErrorLevel.notice) end
		return false
	end
	self.__exptime__ = self.Conf.ccGlobalRuleExptimeSecond
	self:flush()
	return self
end

function NgxCCGlobalDict:set(line,ac)
	local succ, err, forcible = self.belialCCGlobalDict:add(line,ac,self.__exptime__)
	--内存不足提示
	if not succ then self:toLog("belial_cc_global  error:" .. err,self._ErrorLevel.notice) end
	if forcible then self:toLog("belial_cc_global  will be full",self._ErrorLevel.notice)  end
end

function NgxCCGlobalDict:get(k)
	return self.belialCCGlobalDict:get(k)
end

function NgxCCGlobalDict:replace(k,v)
	self.belialCCGlobalDict:replace(k,v,self.__exptime__)
end

function NgxCCGlobalDict:incr(k)
	self.belialCCGlobalDict:incr(k,1)
end

function NgxCCGlobalDict:delete(k)
	self.belialCCGlobalDict:delete(k)
end

function NgxCCGlobalDict:flush()
	self.belialCCGlobalDict:flush_all() 
end


--global denyip ngxShareDict
NgxGlobalDenyIpDict = _Object:BelialFactory({
		belialglobalDenyIpDict=nil,
		__exptime__ = 86400 --exptime
})

function NgxGlobalDenyIpDict:new()
	self.belialglobalDenyIpDict = ngx.shared.belial_global_deny_ip
	if self.belialglobalDenyIpDict == nil then
		self:toLog("belial_global_deny_ip is not defined in nginx.conf",self._ErrorLevel.notice)
		return false
	end
	
	self.__exptime__ = self.Conf.globaldenyIpNgxShareDictExptimeSecond
	self:flush()
	return self
end

function NgxGlobalDenyIpDict:set(line,ac,exptime)
	exptime = exptime == 0 and self.__exptime__ or exptime
	local succ, err, forcible = self.belialglobalDenyIpDict:add(line,ac,exptime)
	--内存不足提示
	--if not succ then self:toLog("belialglobalDenyIpDict  error:" .. err,self._ErrorLevel.error) end
	if forcible then self:toLog("belial_global_deny_ip  will be full",self._ErrorLevel.notice)  end
end

function NgxGlobalDenyIpDict:get(k)
	return self.belialglobalDenyIpDict:get(k)
end

function NgxGlobalDenyIpDict:flush()
	self.belialglobalDenyIpDict:flush_all() 
end


BlShareDict =  NgxShareDict:new()

IpAccessDict = denyIpAccessDict:new()

audoDenyDict = NgxAutoDenyDict:new()

ccDict = NgxCCDict:new()

ccGlobalDict = NgxCCGlobalDict:new()

globalDenyIpDict = NgxGlobalDenyIpDict:new()






