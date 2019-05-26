package com.stableforever.security.masking.jackson;

import com.google.common.base.Strings;
import com.stableforever.security.masking.Sensitive;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * JSON字符串脱敏工具实现类
 *
 * @author colin
 * @version 0.1
 */
public class JsonStringDesensitizerImpl implements JsonStringDesensitizer {
    /**
     * 敏感字段缓存
     */
    private final Map<Class, Map<String, Sensitive>> SENSITIVE_FIELD_CACHE_MAP = new ConcurrentHashMap<>();
    /**
     * 第三敏感字段更新时用到的锁
     */
    private final ReentrantLock SENSITIVE_FIELD_CACHE_MAP_LOCK = new ReentrantLock(false);
    private final DesensitizerRegistry registry;
    private final boolean enabled;
    private final String classPrefix;

    public JsonStringDesensitizerImpl(DesensitizerRegistry registry, boolean enabled, String classPrefix) {
        this.registry = registry;
        this.enabled = enabled;
        this.classPrefix = classPrefix;
    }

    /**
     * 脱敏方法
     *
     * @param rawValue
     * @param modelType
     * @param fieldName
     * @return
     */
    @Override
    public Object desensitive(Object rawValue, Class modelType, String fieldName) {
        // 检查包名
        if (null == fieldName || null == rawValue || !enabled || !modelType.getPackage().getName().startsWith(this.classPrefix)) {
            return rawValue;
        }
        Map<String, Sensitive> fields = getSensitiveFields(modelType);
        // 只有字段在敏感字段列表当中出现，然后rawValue是字符串是才做处理
        if (!fields.containsKey(fieldName) || !(rawValue instanceof CharSequence) || Strings.isNullOrEmpty((String) rawValue)) {
            return rawValue;
        }
        Sensitive sensitive = fields.get(fieldName);
        return registry.lookup(sensitive).desensitize((String) rawValue);
    }

    /**
     * 读取特定类型的敏感字段
     *
     * @param type
     * @return type当中包含的敏感字段
     */
    private Map<String, Sensitive> getSensitiveFields(Class type) {
        if (SENSITIVE_FIELD_CACHE_MAP.containsKey(type)) {
            return SENSITIVE_FIELD_CACHE_MAP.get(type);
        }
        final Map<String, Sensitive> result = new HashMap<>();
        SENSITIVE_FIELD_CACHE_MAP_LOCK.lock();
        try {
            Set<Field> fieldSet = new HashSet<>();
            Field[] fields = type.getDeclaredFields();
            for (Field f : fields) {
                if (f.isAnnotationPresent(Sensitive.class)) {
                    fieldSet.add(f);
                }
            }
            fieldSet.forEach(item -> {
                result.put(item.getName(), item.getAnnotation(Sensitive.class));
            });
            // 父类当中可能也存在相关的字段需要处理
            Class superClass = type.getSuperclass();
            if (superClass != null && superClass != Object.class) {
                result.putAll(getSensitiveFields(superClass));
            }
            // 添加到缓存
            SENSITIVE_FIELD_CACHE_MAP.put(type, result);
        } finally {
            SENSITIVE_FIELD_CACHE_MAP_LOCK.unlock();
        }
        return result;
    }
}
