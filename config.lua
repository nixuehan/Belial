-----------------------------------------------------------------------------
-- Belial web waf
-- Author: 逆雪寒
-- Copyright (c) 2013
-- 
-----------------------------------------------------------------------------

local Conf = {
-----------------------------------------------------------------------------

	belialFileLogPath = "/data/cake/log.belial",
	attackHtmlPageName = "",
	regularRule = "default", 
	
	allowIpAccess = {},
	alloAccessSpidersIp = {},
	denyIPAccess = "/data/denyAccess.ip",--example：/data/denyAccess.ip 
	globaldenyIpNgxShareDictExptimeSecond = 3600,
	
	toLog = "On",
	
	cookieMatch = "On", 
	postMatch   = "On", 
	whiteModule = "On", 
	ngxPathInfoFixModule = "On",
	autoDenyIpModule = "On", 
	ccGlobalLog = "On", 
	ccMatch = "On", 
	

-----------------------------------------------------------------------------

	notAllowUploadFileExtension = {".php"}, 
	
-----------------------------------------------------------------------------	
	getTogether = "Off",
	
	webProjectRootDirectory = "/usr/local/www/nginx",
	allowAccessPostFilePath = "/data/allow.belial",
	rejectPostLogPath = "/data/cake/reject.belial", 
	
-------------------------------------------------------------------------------

	attackAmount = 10, 
	autoDenyIpValidSecond = 86400, 
	autoDenyRuleExptimeSecond = 86400,
	
-----------------------------------------------------------------------------
	
	ccGlobalAmount = 240, 
	ccGloablLogPath = "/data/cake/log.ccGlobal",
	ccGlobalRuleExptimeSecond = 60, 
	
	ccDebug = "On", 
	ccDebugRequestAmount = 60, 
	ccDebugLogPath = "/data/cake/log.ccDebug", 
	
	ccDenyIpValidSecond = 36400, 
	ccDenyTagExptimeSecond = 60 
}

return Conf