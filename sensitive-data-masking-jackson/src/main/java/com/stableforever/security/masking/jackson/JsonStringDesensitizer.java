package com.stableforever.security.masking.jackson;

/**
 * JSON字符串的脱敏接口
 * @author colin
 * @version 0.1
 */
public interface JsonStringDesensitizer {
    /**
     * 脱敏方法
     * @param rawValue
     * @param modelType
     * @param fieldName
     * @return
     */
    Object desensitive(final Object rawValue, Class modelType, String fieldName);
}
