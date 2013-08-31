-----------------------------------------------------------------------------
-- Belial web waf
-- Author: 逆雪寒
-- Copyright (c) 2013 半夜三更
-----------------------------------------------------------------------------


_client_ip_ = getClientIp()
_host_ = ngx.req.get_headers()["Host"]
_request_url_ = ngx.var.request_uri
_self_url_ = _host_ .. _request_url_


function attackLog(way,tags)
	Log:set({errorPageContent ="please stop attack",toBelialLog =  way .. "::" .. "attack is coming" .."["..ngx.unescape_uri(_self_url_).."]",tags = "attack"})
end


--通行ip
if Conf.allowIpAllAccess then
	if inTable(Conf.allowIpAllAccess,_client_ip_) then
		return
	end
end

--基本防御

	
local getArgs = ngx.req.get_uri_args() ; _rqdGet = ""
if getArgs then
	for k,v in pairs(getArgs) do
		if type(v) == "table" then
			_rqdGet = _rqdGet .. table.concat(v," ")
		else
			_rqdGet = v
		end
		
		if _rqdGet and type(_rqdGet) ~= "boolean" then
			_rqdGet = ngx.unescape_uri(_rqdGet)
			if ngx.re.match(_rqdGet,_baseRegexFilterRule.get,"isjo") then 
				__debugOutput("$$".._rqdGet.."$$")
				attackLog("Get") 
			end
		end
	end
end



local function explode (_str,seperator)
	local pos, arr = 0, {}
		for st, sp in function() return string.find( _str, seperator, pos, true ) end do
			table.insert( arr,string.sub( _str, pos, st-1 ))
			pos = sp + 1
		end
	table.insert( arr, string.sub( _str, pos ) )
	return arr
end

-- post 防御
--Content-Disposition: form-data; name="attachment_1"; filename="<D2><BB><C4><A8><D0><B1><D1><F4>.jpg"
--Content-Type: image/jpeg
--Content-Disposition: form-data; name="atc_title"
--
if Conf.postMatch == "On" then
	if ngx.var.request_method == "POST" then
		ngx.req.read_body()
		local receive_headers = ngx.req.get_headers()  
		-- 获取boundary
		local boundary = string.match(receive_headers["content-type"],"boundary=(.+)")
		if boundary then  -- mutil form
			boundary = "--" .. boundary
			local allbody = ngx.req.get_body_data()
			local allbodytable = explode(allbody,boundary)
			for _,v in ipairs(allbodytable) do
				local _fileData = string.match(v,'Content%-Disposition: form%-data; name=".+"; filename=')
				if not _fileData then  --不是附件字段  做过滤判断
					local now = string.gsub(v,'Content%-Disposition: form%-data; name=".+"',"")
					now = string.gsub(now,'\r\n\r\n',"")
					
--					__debugOutput("$$"..v.."$$")
--					__debugOutput("$$"..now.."$$")
					
					now = ngx.unescape_uri(now)
					if ngx.re.match(now,_baseRegexFilterRule.post,"isjo") then 
						__debugOutput("$$"..now.."$$")
						attackLog("multipartPost") 
					end
				end
			end
		else
			local postArgs = ngx.req.get_post_args() ; _rqdPost = ""
			for k,v in pairs(postArgs) do
				if type(v) == "table" then
					_rqdPost = table.concat(v," ")
				else
--					__debugOutput("||"..k.."||")
					_rqdPost = v
				end
				_rqdPost = ngx.unescape_uri(_rqdPost)
				if ngx.re.match(_rqdPost,_baseRegexFilterRule.post,"isjo") then
					__debugOutput("$$".._rqdPost.."$$")
					attackLog("Post") 
				end
			end
		end
		--if string.sub(ngx.req.get_headers()["content-type"],1,20) ~= "multipart/form-data;" then
--			local postArgs = ngx.req.get_post_args() ; _rqdPost = ""
--			if postArgs then
--				for k,v in pairs(postArgs) do
--					
--					if type(v) == "table" then
--							_rqdPost = ngx.req.get_body_data()
--					else
--						_rqdPost = ngx.req.get_body_data()
--						getPostContentNofile(_rqdPost)
--						_rqdPost = v
--					end
--					-- not file upload
--					if string.match(k,".*Content%-Disposition:%s+form%-data;%s+name") or string.match(k,"^[a-zA-Z_%-]+$") then
--						if _rqdPost and type(_rqdPost) ~= "boolean" then
--							_rqdPost = ngx.unescape_uri(_rqdPost)
--							if string.match(_rqdPost,"%w") then
--								if ngx.re.match(_rqdPost,_baseRegexFilterRule.post,"isjo") then 
--									__debugOutput(k .."::>" .._rqdPost .."<::")
--									attackLog("Post") 
--								end
--							end
--						end
--					end
--				end
--			end
		--end
	end
end

-- cookie防御
if Conf.cookieMatch == "On" then
	local _cookie = ngx.var.http_cookie
	if _cookie then
		local requestCookie = ngx.unescape_uri(_cookie)
		if ngx.re.match(requestCookie,_baseRegexFilterRule.cookie,"isjo") then 
			__debugOutput("$$"..requestCookie.."$$")
			attackLog("cookie") 
		end
	end 
end
	    

if Conf.cgiPathinfoModule == "On" then
	local request_uri = _request_url_
	if request_uri then
		if ngx.re.match(ngx.unescape_uri(request_uri),_baseRegexFilterRule.cgiPath,"isjo") then
			__debugOutput("$$"..ngx.unescape_uri(request_uri).."$$")
			attackLog("cgiFixPath")
		end
	end
	
end


-- 白名单防护
if Conf.whiteModule == "On" then
	if string.lower(ngx.req.get_method()) == "post" then
		
		local requestAbsolutePath = ngx.var.document_root .. ngx.var.document_uri
		
		if not ngx.var.document_root or not ngx.var.document_uri then 
			Log:toBelial("ngx.var.document_root or ngx.var.document_uri is empty","error")
			return
		end
		
		--收集白名单 post
		local ac,_ = ngxShareDict:get(requestAbsolutePath)
		local fullPathRq = string.sub(requestAbsolutePath,string.len(Conf.webProjectRootDirectory)+1)
		
		
		if Conf.getTogether == "On" then
			if ac == nil then
				local rqFD = io.open(requestAbsolutePath,"r")
				
				if rqFD then
					local fd = io.open(_Conf.whiteListFileName,"ab")
					if fd then
						
						fd:write(fullPathRq.."\n")
						fd:flush()
						fd:close()
						--防重复
						ngxShareDict:set(requestAbsolutePath,_WhiteListState["valid"])
					end
				end
			end
			
		else
			--防御
			if ac == nil or ac == _WhiteListState["down"] then
				local fd = io.open(_Conf.rejectList,"ab")
				if fd then
					fd:write(ngx.localtime() .."	".. fullPathRq.."\n")
					fd:flush()
					fd:close()
				end
				attackLog("whiteList")
			end
		end
	
	end

end
