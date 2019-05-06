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




## 一些计划 #TODO

- [x] 可以将 外部 URL 列表导入 burp
- [x] 增加 DNS log API 
- [ ] 顺带可以读一读 DNSlog API 相关的代码
- [ ] 集成到被动扫描器
      小明师傅写的文档
      http://wp.blkstone.me/2018/10/zto-distributed-passive-scan-in-action/
- [ ] 被动扫描器增加 SSRF 检测功能
- [ ] 测试 XSStrike 集成到 被动扫描器
- [ ] Eason 备份文件扫描
      做这个功能的时候可以 参考 Burp Suite 的 Content Discovery
      https://github.com/H4ckForJob/dirmap

- [ ] 增加 XXE ftp OOB 的功能


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


### 导入外部 URL 到 Burp

load_url.py

将 外部 URL 文件导入到 Burp
之后使用 高级范围控制 和 Burp 爬虫，获取大量目标系统的 URL 。
将这些 URL 丢给其他组件进行扫描。

