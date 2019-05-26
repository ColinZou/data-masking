package com.stableforever.security.masking;

import lombok.extern.slf4j.Slf4j;

/**
 * 字符串脱敏工具
 *
 * @author colin
 * @version 0.1
 */
public interface Desensitizer {
    /**
     * 默认的mask字符
     */
    String DEFAULT_MASK_CHAR = "*";

    @Slf4j
    class Builder {
        private DesensitizerImpl item = new DesensitizerImpl();
        private static final int INVALID_ARGUMENT_ERROR_CODE = 101010101;

        private Builder() {
        }

        /**
         * 生成脱敏工具
         *
         * @return
         */
        public Desensitizer build() {
            MaskMode mode = item.getMode();
            if (mode == MaskMode.HEAD && item.getFixedHeaderSize() > 0) {
                log.warn("Fixed header bigger than 0 when mode is {}", mode);
            }
            if (mode == MaskMode.TAIL && item.getFixedTailorSize() > 0) {
                log.warn("Fixed tailor bigger than 0 when mode is {}", mode);
            }
            return item;
        }

        /**
         * 设置工作模式
         *
         * @param maskMode
         * @return
         */
        public Builder sethMode(MaskMode maskMode) {
            if (null == maskMode) {
                throw new IllegalArgumentException("maskMode cannot be null");
            }
            item.setMode(maskMode);
            return this;
        }

        /**
         * 设置遮挡字符
         *
         * @param maskChar
         * @return
         */
        public Builder setMaskChar(char maskChar) {
            if (maskChar == 0) {
                throw new IllegalArgumentException("Invalid mask char");
            }
            item.setMaskChar(new String(new char[]{maskChar}));
            return this;
        }

        /**
         * 设置不被mask的开始字符长度
         *
         * @param size
         * @return
         */
        public Builder setFixedHeaderSize(int size) {
            if (size <= 0) {
                throw new IllegalArgumentException("header must be larger than 0");
            }
            item.setFixedHeaderSize(size);
            return this;
        }

        /**
         * 设置不被mask的结束字符长度
         *
         * @param size
         * @return
         */
        public Builder setFixedTailorSize(int size) {
            if (size <= 0) {
                throw new IllegalArgumentException("header must be larger than 0");
            }
            item.setFixedTailorSize(size);
            return this;
        }

        /**
         * 设置是否自动计算固定部分
         *
         * @param autoFixedPart
         * @return
         */
        public Builder setAutoFixedPart(boolean autoFixedPart) {
            item.setAuto(autoFixedPart);
            return this;
        }
    }

    /**
     * Builder方法
     *
     * @return
     */
    static Builder builder() {
        return new Builder();
    }

    /**
     * 遮挡模式
     */
    enum MaskMode {
        /**
         * 尾部
         */
        TAIL,
        /**
         * 头部
         */
        HEAD,
        /**
         * 中央
         */
        MIDDLE,
    }

    /**
     * 脱敏
     *
     * @param rawString
     * @return
     */
    String desensitize(final String rawString);
}