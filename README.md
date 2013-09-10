Belial
======
写了个waf 自己用 。这个程序是基于 nginx lua module .  运行平台是 linux  freebsd 的 nginx 。。 WIN 的 你可以用个 linux 的 nginx 做反向代理 保护后面的服务。

Belial 目前包含的模块有 ： GET 、 POST 、 COOKIE SQL注入防御、文件上传控制、POST白名单审核、nginx路径解释防御、封IP、
自动拦截防御 cc防御。  防御面向的语言是  php .. 其他的～不做考虑 。启用 belial waf 在性能损耗上基本可以忽略～

微博: http://weibo.com/shajj

系列使用教程

1、nginx lua 和 belial waf 安装配置  http://www.dwz.cn/awGdk

2、我线上的配置(包括config.lua 和 nginx.conf的配置)  https://github.com/nixuehan/Belial/tree/master/example

3、belial waf 目录结构和文件解释  http://dwz.cn/axyOW

4、配置文件参数解释 http://www.dwz.cn/awCYM

5、基本防御机制  http://dwz.cn/axfxQ

6、post白名单机制   http://dwz.cn/axBrV

7、自动拦截机制  http://dwz.cn/axD74

8、CC防御机制  http://dwz.cn/axGjD

9、日志文件  http://dwz.cn/axGN3

