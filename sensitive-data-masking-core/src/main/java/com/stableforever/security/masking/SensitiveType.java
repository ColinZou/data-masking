package com.stableforever.security.masking;

/**
 * 敏感类型
 *
 * @author colin
 * @version 0.1
 */
public enum SensitiveType {
    /**
     * 中文人名
     */
    CHINESE_NAME,
    /**
     * 身份证号
     */
    ID_CARD,
    /**
     * 电话号码
     */
    PHONE_NUMBER,
    /**
     * 地址
     */
    ADDRESS,
    /**
     * 电子邮件
     */
    EMAIL,
    /**
     * 银行卡
     */
    BANK_CARD,
    /**
     * 密码
     */
    PASSWORD,
    /**
     * 普通号码
     */
    GENERIC,
    ;

}
