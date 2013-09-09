-----------------------------------------------------------------------------
-- Belial web waf
-- Author: 逆雪寒
-- Copyright (c) 2013
-- 
-----------------------------------------------------------------------------

local Conf = {
-----------------------------------------------------------------------------

	belialFileLogPath = "/data/cake/log.belial",
	isBackend = false, 
	attackHtmlPageName = "",
	regularRule = "default", 
	
	allowIpAccess = {},
	alloAccessSpidersIp = {},
	denyIPAccess = "",--example：/data/denyAccess.ip 
	globaldenyIpNgxShareDictExptimeSecond = 3600,
	
	toLog = "On",
	
	cookieMatch = "On", 
	postMatch   = "On", 
	whiteModule = "Off", 
	ngxPathInfoFixModule = "Off",
	autoDenyIpModule = "Off", 
	ccGlobalLog = "Off", 
	ccMatch = "Off", 
	

-----------------------------------------------------------------------------

	notAllowUploadFileExtension = {".php"}, 
	
-----------------------------------------------------------------------------	
	getTogether = "Off",
	
	webProjectRootDirectory = "/data/www/ting",
	allowAccessPostFilePath = "/data/belial/allow.belial",
	rejectPostLogPath = "/data/belial/cake/reject.belial", 
	
-------------------------------------------------------------------------------

	attackAmount = 10, 
	autoDenyIpValidSecond = 86400, 
	autoDenyRuleExptimeSecond = 86400,
	
-----------------------------------------------------------------------------
	
	ccGlobalAmount = 240, 
	ccGloablLogPath = "/data/belial/cake/log.ccGlobal",
	ccGlobalRuleExptimeSecond = 60, 
	
	ccDebug = "On", 
	ccDebugRequestAmount = 60, 
	ccDebugLogPath = "/data/belial/cake/log.ccDebug", 
	
	ccDenyIpValidSecond = 36400, 
	ccDenyTagExptimeSecond = 60 
}

return Conf