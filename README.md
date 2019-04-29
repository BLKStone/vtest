# VTestNG

## 说明

VTestNG 是 VTest 的魔改版本。




改动如下：

1 重新组织整理项目目录结构

2 使用 pprint 替换部分 print 

3 修改了 command-line interface 的实现

4 增加了一些异常处理，增强程序健壮性

5 配置文件统一管理 vtestng_config.py

6 修改数据库结构

7 新增 API 路由

## 调试指南


### mock 

`curl -v http://your_ip/mock/demo1`

### httplog

`curl -v http://your_ip/httplog/{custome_message}`
`curl -v http://45.76.125.91/httplog/test`

### api


```
curl -v http://45.76.125.91/api/dns/generate
nslookup 2cka9ei4ls.alida.club
curl -v http://45.76.125.91/api/dns/query/2cka9ei4ls
```



