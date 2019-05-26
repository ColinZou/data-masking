package com.stableforever.security.masking;

/**
 * 普通脱敏处理的数据遮挡模式
 * @author colin
 * @version 0.1
 */
public enum GenericMaskMode {
    /**
     * 开始部分mask
     */
    HEAD,
    /**
     * 结束部分mask
     */
    TAIL,
    /**
     * 中间mask
     */
    MIDDLE
}
