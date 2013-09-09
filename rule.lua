-----------------------------------------------------------------------------
-- Belial web waf
-- Author: 逆雪寒
-- Copyright (c) 2013 半夜三更
-- 
-- 
-- 
-----------------------------------------------------------------------------

--拦截规则
local regularRule =
{
	--belial waf default rule。dont delete
	default = {
		get = "'|(and|or)\\b.+?(>|<|=|\\bin|\\blike)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)|(\\.\\.\\/)+|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
		
		post = "base64_decode|\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT.+?INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE).+?(TABLE|DATABASE)|\\.\\/|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
		
		cookie = "\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)",
		
		ngxPathInfoFix = "\\..*\\/.*php",
	},
	
	--适合俺公司的规则
	ziqing = {
		get = "(and|or)\\b.+?(>|<|=|\\bin|\\blike)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)|(\\.\\.\\/)+|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
		
		post = "base64_decode|\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT.+?INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE).+?(TABLE|DATABASE)|\\.\\/|^\\/?[a-zA-Z]+(\\/[a-zA-Z]+)+$",
		
		cookie = "\\b(and|or)\\b.{1,6}?(=|>|<|\\bin\\b|\\blike\\b)|\\/\\*.+?\\*\\/|<\\s*script\\b|\\bEXEC\\b|UNION.+?SELECT|UPDATE.+?SET|INSERT\\s+INTO.+?VALUES|(SELECT|DELETE).+?FROM|(CREATE|ALTER|DROP|TRUNCATE)\\s+(TABLE|DATABASE)",
		
		ngxPathInfoFix = "\\..*\\/.*php",
	},
}



--cc规则
-- urlRegular,ccHackAmount
local ccUrlList = 
{
	{"read.php\\?tid=\\d+?",120},
    {"searchthread\\.php",120},
    {"login\\.php",120},
    {"register\\.php",120},
    {"thread\\.php",120},
    {"post1\\.php",60},
	{"item\\/(.+?)\\.html",120}, --伪静态url
}

return {regularRule=regularRule,ccUrlList=ccUrlList}