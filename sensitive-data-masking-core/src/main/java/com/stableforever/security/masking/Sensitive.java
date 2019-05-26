package com.stableforever.security.masking;

import java.lang.annotation.*;

/**
 * 敏感数据的注解
 *
 * @author colin
 * @version 0.1
 */
@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface Sensitive {
    /**
     * 类型
     *
     * @return 类型
     */
    SensitiveType value();

    /**
     * 一般的数字的mask模式
     *
     * @return
     */
    GenericMaskMode numberMaskMode()
            default GenericMaskMode.MIDDLE;

}
