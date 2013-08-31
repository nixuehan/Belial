-----------------------------------------------------------------------------
-- Belial web waf
-- Author: 逆雪寒
-- Copyright (c) 2013 半夜三更
-----------------------------------------------------------------------------

local BlHeader = ngx.req.get_headers()
local BlRequestUrl = ngx.var.request_uri
local BlSelfUrl = BlHeader["Host"] .. BlRequestUrl
local Blunescape_uri = ngx.unescape_uri
local BLrequest_method = ngx.var.request_method
local BLrequest_filename = ngx.var.request_filename
local BLtime = ngx.time()

function _Object:attackLog(tag)
	self:saveFile("["..tag .. "]" ..self:clientInfoLog() .."=>>" .. Blunescape_uri(BlSelfUrl),self._Conf.belialFileName)
	self:errorPage("please stop attack")
end

function _Object:log(msg,tag)
	self:toLog(msg .." "..self:clientInfoLog(),tag)
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
	if audoDenyDict then
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


--autoDenyIp
-- if request file is  php
if ngx.re.match(BLrequest_filename,".*\\.php$","isjo") then
	if belial.Conf.autoDenyIpModule == "On" then
		if audoDenyDict then
			local _request = audoDenyDict:get(BLrealIp)
			if _request then
				local lastTime,attackAmount,requestAmountMilliseconds = belial:split(_request)
				
				if (BLtime - tonumber(lastTime)) <= belial.Conf.accessFrequencySecond and tonumber(attackAmount) > belial.Conf.attackAmount then --访问频率过快
					
					
					audoDenyDict:replace(BLrealIp,audoDenyDict:format(BLtime,attackAmount,tonumber(requestAmountMilliseconds) + 1))
--					belial:__debugOutput(_request)
					
					belial:log(BlSelfUrl,"autoDenyIp") -- record attack
					ngx.exit(ngx.HTTP_FORBIDDEN)
				end
				audoDenyDict:replace(BLrealIp,audoDenyDict:format(BLtime,attackAmount,requestAmountMilliseconds))
			end
		end
	end
end


--allow ip
if belial.Conf.allowIpAccess then
	if belial:inTable(belial.Conf.allowIpAccess,BLrealIp) then 
		return
	end
end


local denyIpAccessModule = function()
--deny ip
	if belial.Conf.denyIPAccess then
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
					_rqdGet = _rqdGet .. table.concat(v," ")
				else
					_rqdGet = v
				end
				
				if _rqdGet then
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
	if belial.Conf.postMatch == "On" then
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
						local uploadFileExtension = string.match(v,'Content%-Disposition: form%-data; name=".+"; filename=".-(%..-)"')
						
						if not uploadFileExtension then  --不是附件字段  做过滤判断
							local now = string.gsub(v,'Content%-Disposition: form%-data; name=".+"',"")
							now = string.gsub(now,'\r\n\r\n',"")
							
							now = Blunescape_uri(now)
							if ngx.re.match(now,belial._baseRegexFilterRule.post,"isjo") then 
								belial:__debugOutput(">>"..now.."<<")
								_G({msg="multipartPost"})
							end
						else --判断附件扩展名
							if belial.Conf.allowUploadFileExtension then
								if not belial:inTable(belial.Conf.allowUploadFileExtension,string.lower(uploadFileExtension)) then
									belial:__debugOutput(">>"..uploadFileExtension.."<<")
									_G({msg="allowUploadFileExtension"})
								end
							end
						end
					end
				else
					belial:toLog("nginx 's client_max_body_size and client_body_buffer_size is too small","error")
				end
			else
				
				local postArgs = ngx.req.get_post_args() ; _rqdPost = ""
				for k,v in pairs(postArgs) do
					if type(v) == "table" then
						_rqdPost = table.concat(v," ")
					else
						_rqdPost = v
					end
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

-- cookie防御
local cookieSafeModule = function()
	if belial.Conf.cookieMatch == "On" then
		local _cookie = ngx.var.http_cookie
		if _cookie then
			local requestCookie = Blunescape_uri(_cookie)
			if ngx.re.match(requestCookie,belial._baseRegexFilterRule.cookie,"isjo") then 
				belial:__debugOutput(">>"..requestCookie.."<<")
				_G({msg="cookie"})
			end
		end 
	end
end

local ngxPathInfoSafeModule = function()
	if belial.Conf.ngxPathInfoFixModule == "On" then
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
	if belial.Conf.whiteModule == "On" then
		if string.lower(BLrequest_method) == "post" then
			
			local requestAbsolutePath = ngx.var.document_root .. ngx.var.document_uri
			
			if not ngx.var.document_root or not ngx.var.document_uri then 
				belial.toLog("ngx.var.document_root or ngx.var.document_uri is empty","error")
				return
			end
			
			--收集白名单 post
			local ac,_ = BlShareDict:get(requestAbsolutePath)
			local fullPathRq = string.sub(requestAbsolutePath,string.len(belial.Conf.webProjectRootDirectory)+1)
			
			
			if belial.Conf.getTogether == "On" then
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
	cookieSafeModule,
	ngxPathInfoSafeModule,
	allowListSafeModule
})