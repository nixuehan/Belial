-----------------------------------------------------------------------------
-- Belial web waf
-- Author: 逆雪寒
-- Copyright (c) 2013 半夜三更
-----------------------------------------------------------------------------

local BlHeader = ngx.req.get_headers()
local BlRequestUrl = ngx.var.request_uri
local Blunescape_uri = ngx.unescape_uri
local BlSelfUrl = Blunescape_uri(BlHeader["Host"] .. BlRequestUrl)
local BLrequest_method = ngx.var.request_method
local BLrequest_filename = ngx.var.request_filename
local BLtime = ngx.time()

local isPHPhttpRequest,err = ngx.re.match(BLrequest_filename,".+\\.php$","ijo")

function _Object:attackLog(tag)
	self:saveFile("["..tag .. "]" ..self:clientInfoLog() .."=>>" .. BlSelfUrl,self._Conf.belialFileName)
	self:errorPage("please stop attack")
end

function _Object:log(msg,tag)
	self:toLog(msg .." "..self:clientInfoLog(),tag)
end

function _Object:ccDebugLog(msg)
	if not self:_False(self.Conf.ccDebugLogPath) then
		self:cclog(msg .. " "..self:clientInfoLog())
	else
		self:log(msg,"debugCC")
	end
end

function _Object:ccGloablLog(msg)
	if not self:_False(self.Conf.ccGloablLogPath) then
		self:ccGlobalLog(msg .. " "..self:clientInfoLog())
	else
		self:log(msg,"globalCC")
	end
end

function _Object:clientInfoLog()
	return " "..self:getClientIp().." "
			.." ["..ngx.localtime().."] "
			..ngx.status.." "
			..ngx.var.http_user_agent
end


local belial = Belial:new()
local BLrealIp = belial:getClientIp()

-- times | attackAmount | requestAmountMilliseconds

function _G(options)
	if belial._Conf.autoDenyIpModule and audoDenyDict then
		-- 记录攻击ip 计算攻击数量和时间
		local _request = audoDenyDict:get(BLrealIp)
		if _request then
			local times,attackAmount,requestAmountMilliseconds = belial:split(_request)
			
			audoDenyDict:replace(BLrealIp,audoDenyDict:format(BLtime,tonumber(attackAmount)+1,requestAmountMilliseconds))
		else
			audoDenyDict:set(BLrealIp,audoDenyDict:format(BLtime,1,0))
		end
	end
	
	belial:attackLog(options.msg)
end

--lua patch

function _splitFloatToIntegerAndRemainder(floatVar)
	local _var = ngx.re.match(tostring(floatVar),"(\\d+?)\\.(\\d+)","ijo")
	return _var and tonumber(_var[1]),tonumber(_var[2]) or false
end


if not globalDenyIpDict then return end --global ngx share dict must be set

--allow ip
if belial:inTable(belial.Conf.allowIpAccess,BLrealIp) or belial:inTable(belial.Conf.alloAccessSpidersIp,BLrealIp) then 
	return
end

--global deny ip
if globalDenyIpDict then
	if globalDenyIpDict:get(BLrealIp) then
		belial:errorPage("please stop attack")
	end
end

--cc
--global cc log
if belial._Conf.ccGlobalLog and ccGlobalDict then
	if isPHPhttpRequest then
		local hackAmountOrlastTime = ccGlobalDict:get(BLrealIp)
		local li = BLtime * 0.0000000001
		
		if hackAmountOrlastTime then
			local hackAmount,lastTimeSecond = _splitFloatToIntegerAndRemainder(hackAmountOrlastTime)
						
			if (BLtime - lastTimeSecond) <=1 then
				hackAmount = hackAmount + 1
			end
			
			if hackAmount > belial.Conf.ccGlobalAmount then 
				belial:ccGloablLog("[global]".."("..hackAmount..")"..BlSelfUrl)
			end
				
			ccGlobalDict:replace(BLrealIp,hackAmount + li)
		else --init
			ccGlobalDict:set(BLrealIp,1+li)
		end
	end
end

if belial._Conf.ccMatch and ccDict then
	if isPHPhttpRequest then
		if next(belial.CcRule) ~= nil then
			for _,v in pairs(belial.CcRule) do
				if ngx.re.match(BlSelfUrl,v[1],"ijo") then
					local hackAmountOrlastTime = ccDict:get(BLrealIp)
					local li = BLtime * 0.0000000001
					
					if hackAmountOrlastTime then
						local hackAmount,lastTimeSecond = _splitFloatToIntegerAndRemainder(hackAmountOrlastTime)
									
						if (BLtime - lastTimeSecond) <=1 then
							hackAmount = hackAmount + 1
						end
						
						if belial._Conf.ccDebug and hackAmount > belial.Conf.ccDebugRequestAmount then 
							belial:ccDebugLog("["..hackAmount.."]"..BlSelfUrl)
						end
						
						if hackAmount > v[2] then
							belial:log(BlSelfUrl,"ccDenyIp") -- record attack
							ccDict:delete(BLrealIp)
							globalDenyIpDict:set(BLrealIp,true,belial.Conf.ccDenyIpValidSecond)  -- add to global denyip ngxshare dict
							belial:errorPage("please stop attack")
						end

						ccDict:replace(BLrealIp,hackAmount + li)
					else --init
						ccDict:set(BLrealIp,1+li)
					end
				end
			end
		end
	end
end

--autoDenyIp
-- if request file is  php
if isPHPhttpRequest then
	if belial._Conf.autoDenyIpModule then
		if audoDenyDict then
			local _request = audoDenyDict:get(BLrealIp)
			if _request then
				local lastTime,attackAmount,requestAmountMilliseconds = belial:split(_request)
				
				if tonumber(attackAmount) > belial.Conf.attackAmount then
					
					audoDenyDict:delete(BLrealIp)
					--audoDenyDict:replace(BLrealIp,audoDenyDict:format(BLtime,attackAmount,tonumber(requestAmountMilliseconds) + 1))
--					belial:__debugOutput(_request)
					globalDenyIpDict:set(BLrealIp,true,belial.Conf.autoDenyIpValidSecond)
					belial:log(BlSelfUrl,"autoDenyIp") -- record attack
					ngx.exit(ngx.HTTP_NOT_FOUND)
				end
				audoDenyDict:replace(BLrealIp,audoDenyDict:format(BLtime,attackAmount,requestAmountMilliseconds))
			end
		end
	end
end


local denyIpAccessModule = function()
--deny ip
	if not belial:_False(belial.Conf.denyIPAccess) then
		if IpAccessDict:get(BLrealIp) then
			_G({msg="ipDeny"})
		end
	end
end


-- get 防御
local getSaveModule = function()
	
	local getArgs,_rqdGet= ngx.req.get_uri_args(),""
	if getArgs then
		for k,v in pairs(getArgs) do
			if type(v) ~= "boolean" then
				if type(v) == "table" then
					local _v,tableConcatReturn = pcall(function()  return table.concat(v," ")   end)
					if _v then
						_rqdGet =  tableConcatReturn
					else
						belial:__debugOutput(">>"..tableConcatReturn.."<<") --temporary debug
						_G({msg="debug"})
						_rqdGet = false
					end
				else
					_rqdGet = v
				end
				if not belial:_False(_rqdGet) then
					_rqdGet = Blunescape_uri(_rqdGet)
					
					if ngx.re.match(_rqdGet,belial._baseRegexFilterRule.get,"isjo") then 
						belial:__debugOutput(">>".._rqdGet.."<<")
						_G({msg="get"})
					end
				end
			end
		end
	end
end


-- post 防御

local postSafeModule = function () 
	if belial._Conf.postMatch then
		if BLrequest_method == "POST" then
			-- 获取boundary
			local boundary = string.match(BlHeader["content-type"],"boundary=(.+)")
			if boundary then  -- mutil form
				boundary = "--" .. boundary
				ngx.req.read_body()
				local allbody = ngx.req.get_body_data()
				if allbody then
					local allbodytable = belial:explode(allbody,boundary)
					for _,v in ipairs(allbodytable) do
						if v ~= "" and v then
							local uploadFileExtension,err = ngx.re.match(v,"Content-Disposition:\\s+form-data; name=\".+?\";\\s+filename=\".+(\\..+?)\"","ijo")
							
							if not uploadFileExtension then  --不是附件字段  做过滤判断
								local now = string.gsub(v,'Content%-Disposition: form%-data; name=".+"',"")
								now = string.gsub(now,'\r\n\r\n',"")
								
								now = Blunescape_uri(now)
								if ngx.re.match(now,belial._baseRegexFilterRule.post,"isjo") then 
									belial:__debugOutput(">>"..now.."<<")
									_G({msg="multipartPost"})
								end
							else --判断附件扩展名
								if belial.Conf.notAllowUploadFileExtension then
									uploadFileExtension = uploadFileExtension[1]
									if belial:inTable(belial.Conf.notAllowUploadFileExtension,string.lower(uploadFileExtension)) then
										belial:__debugOutput(">>"..uploadFileExtension.."<<")
										_G({msg="notAllowUploadFileExtension"})
									end
								end
							end
						end
					end
				else
					belial:toLog("nginx 's client_max_body_size and client_body_buffer_size is too small","notice")
				end
			else
				local postArgs = ngx.req.get_post_args() ; _rqdPost = ""
				for k,v in pairs(postArgs) do
					if type(v) ~= "boolean" then
						if type(v) == "table" then
							_rqdPost = table.concat(v," ")
						else
							_rqdPost = v
						end
						if not belial:_False(_rqdPost) then
							_rqdPost = Blunescape_uri(_rqdPost)
							if ngx.re.match(_rqdPost,belial._baseRegexFilterRule.post,"isjo") then
								belial:__debugOutput(">>".._rqdPost.."<<")
								_G({msg="Post"})
							end
						end
					end
				end
			end
		end
	end
end
-- cookie防御

if isPHPhttpRequest then
	
	if belial._Conf.cookieMatch then
		local _cookie = ngx.var.http_cookie
		if _cookie then
			for _,v in string.gmatch(_cookie,"(%w+)=([^;%s]+)") do
				local requestCookie = Blunescape_uri(v)
				if ngx.re.match(requestCookie,belial._baseRegexFilterRule.cookie,"isjo") then 
					belial:__debugOutput(">>"..requestCookie.."<<")
					_G({msg="cookie"})
				end
			end
		end 
	end
end

local ngxPathInfoSafeModule = function()
	if belial._Conf.ngxPathInfoFixModule then
		if BlRequestUrl then
			if ngx.re.match(Blunescape_uri(BlRequestUrl),belial._baseRegexFilterRule.ngxPathInfoFix,"isjo") then
				belial:__debugOutput(">>"..Blunescape_uri(BlRequestUrl).."<<")
				_G({msg="ngxPathInfo"})
			end
		end
		
	end
end

local allowListSafeModule = function()
-- 白名单防护
	if belial._Conf.whiteModule and BlShareDict then
		if string.lower(BLrequest_method) == "post" then
			
			local requestAbsolutePath = ngx.var.document_root .. ngx.var.document_uri
			
			if not ngx.var.document_root or not ngx.var.document_uri then 
				belial.toLog("ngx.var.document_root or ngx.var.document_uri is empty","notice")
				return
			end
			
			--收集白名单 post
			local ac,_ = BlShareDict:get(requestAbsolutePath)
			local fullPathRq = string.sub(requestAbsolutePath,string.len(belial.Conf.webProjectRootDirectory)+1)
			
			
			if belial._Conf.getTogether then
				if ac == nil then
					local rqFD = io.open(requestAbsolutePath,"r")
					
					if rqFD then
						local fd = io.open(belial._Conf.whiteListFileName,"ab")
						if fd then
							
							fd:write(fullPathRq.."\n")
							fd:flush()
							fd:close()
							--防重复
							BlShareDict:set(requestAbsolutePath,belial._ListState["valid"])
						end
					end
				end
				
			else
				--防御
				if ac == nil or ac == belial._ListState["down"] then
					local fd = io.open(belial._Conf.rejectList,"ab")
					if fd then
						fd:write(ngx.localtime() .."	".. fullPathRq.."\n")
						fd:flush()
						fd:close()
					end
					belial:__debugOutput(">>"..requestAbsolutePath.."<<")
					_G({msg="whiteList"})
				end
			end
		end
	end
end


belial:start({
	denyIpAccessModule,
	getSaveModule,
	postSafeModule,
	ngxPathInfoSafeModule,
	allowListSafeModule
})