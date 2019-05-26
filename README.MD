# 数据脱敏

## 一、介绍

用于处理敏感数据输出时数据脱敏。如人名“张山山”，输出时显示为“张*山”。数据脱敏的应用场景比较多，目前也不有少的人实现了代码。暂时没有看到完整的可以直接拿来就用的封装。

## 二、使用方法

### 1. 下载本代码并执行mvn install

```bash
git clone https://github.com/ColinZou/data-masking.git
cd data-masking && mvn install
```

稍后再花些时间把代码上传到maven中央仓库。

### 2. 引入starter

```xml
<dependency>
    <groupId>com.stableforever</groupId>
    <artifactId>sensitive-data-masking-jackson-spring-boot-starter</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>	
```

### 3. 启用

#### a). 在配置当中添加以下配置项：

```properties
web.desensitizer.enabled=true
web.desensitizer.classNamePrefix=com.
```

web.desensitizer.classNamePrefix需要设置为你的数据模型包路径。

#### b). 在需要做脱敏处理的字段上添加注解

```java
@Data
public class SimpleModel {
    @Sensitive(value = SensitiveType.CHINESE_NAME)
    private String fullName;
}
```

详见examples/data-masking-test