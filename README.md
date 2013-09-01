Belial
======

花了几天时间写了个waf 


1、首先安装 nginx lua 模块。 咋装我这里就不介绍了，自己百度或者谷歌都行  http://dwz.cn/belial

2、 nginx.conf 配置

    lua_package_path "/data/?.lua";   #lua路径  
    lua_shared_dict belial 100m;   #当开启 post白名单模块 必须设置这个
    lua_shared_dict belialAutoDeny 100m; #当开启自动拦截 必须设置这个
    init_by_lua_file /data/init.lua;  
    lua_need_request_body on;
    access_by_lua_file /data/belial.lua;
    

3、 重启下nginx (*注意  以后修改 配置文件 config.lua  只需要 nginx reload) 然后 belial waf 就启动了。 重启nginx 有错误～ 微博@我吧
http://www.weibo.com/shajj 

下面介绍下 belial waf 的所有功能。 模块的开启和关闭都是再  config.lua 里进行配置。 配置完 只需要 nginx reload 就生效鸟


1、全局配置

belialFileLogPath = "/data/cake/log.belial"   -- 日志的目录，所有的错误信息和攻击拦截信息所在

isBackend = true  -- 如果 belial waf 位于后端 那就true。否则获得的请求IP不准确

attackHtmlPageName = "", --自定义拦截页面 文件路径  例如:/data/belial.html

toLog = "On", -- 攻击信息是否纪录到日志文件

2、文件上传模块

allowUploadFileExtension = {".jpg",".jpeg",".bmp",".gif",".png"}, --允许上传的扩展名

3、cookie过滤模块

cookieMatch = "On",  -- 是否对cookie进行关键字匹配判断

4、post过滤模块

postMatch   = "On",   -- 是否对post请求进行关键字匹配判断

5、post白名单模块

whiteModule = "On"  --是否开POST白名单

getTogether = "Off"  --是否开启收集。*可以先开启 收集个几天，然后获得大部分得post白名单之后再关闭。
注意：只有 whiteModule = "On" 和 getTogether = "Off" 后 白名单拦截机制才正式启动

webProjectRootDirectory = "/usr/local/www/nginx", --你网站的www目录(根目录) *记得不带斜杠(/)

allowAccessPostFilePath = "/data/allow.belial", -- 白名单,一个记录一行

rejectPostLogPath = "/data/cake/reject.belial", -- post被拦截的记录



