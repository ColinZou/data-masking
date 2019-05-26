package com.stableforever.security.masking.jackson;

import com.stableforever.security.masking.Desensitizer;
import com.stableforever.security.masking.Sensitive;

/**
 * 脱敏工具注册表
 * @author colin
 * @version 0.1
 */
public interface DesensitizerRegistry {
    /**
     * 寻找实现
     * @param sensitive
     * @return
     */
    Desensitizer lookup(Sensitive sensitive);
}
