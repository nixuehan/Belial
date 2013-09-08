Belial
======
写了个waf 自己用 。这个程序是基于 nginx lua module .  运行平台是 linux  freebsd 的 nginx 。。 WIN 的 你可以用个 linux 的 nginx 做反向代理 保护后面的服务。

Belial 目前包含的模块有 ： GET 、 POST 、 COOKIE SQL注入防御、文件上传控制、POST白名单审核、nginx路径解释防御、封IP、
自动拦截防御 cc防御。 


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


配置文件参数解释
