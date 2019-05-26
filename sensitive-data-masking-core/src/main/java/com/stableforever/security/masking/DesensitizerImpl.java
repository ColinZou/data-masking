package com.stableforever.security.masking;

import com.google.common.base.Strings;
import lombok.Getter;
import lombok.Setter;

/**
 * 脱敏工具实现类
 *
 * @author colin
 * @version 0.1
 */
public class DesensitizerImpl implements Desensitizer {
    /**
     * 工作模式
     */
    @Getter
    private MaskMode mode = MaskMode.HEAD;
    /**
     * 固定的头部字符数量
     */
    @Getter
    private int fixedHeaderSize = 0;
    /**
     * 固定的尾部字符数量
     */
    @Getter
    private int fixedTailorSize = 3;
    /**
     * mask字符
     */
    @Getter
    @Setter
    private String maskChar = Desensitizer.DEFAULT_MASK_CHAR;
    /**
     * 自动模型
     * 即根据mode来自动决定如何mask
     */
    @Getter
    @Setter
    private boolean auto;

    protected void setMode(MaskMode mode) {
        this.mode = mode;
        // 设置工作模式时，自动把特定fixed part归零
        // 如设置mask头部，则把头部的固定数量归零
        switch (mode) {
            case TAIL:
                this.fixedTailorSize = 0;
                break;
            case HEAD:
                this.fixedHeaderSize = 0;
                break;
            case MIDDLE:
            default:
                //  do nothing
                break;
        }
    }

    protected void setFixedHeaderSize(int fixedHeaderSize) {
        if (mode != MaskMode.HEAD) {
            this.fixedHeaderSize = fixedHeaderSize;
        }
    }

    protected void setFixedTailorSize(int fixedTailorSize) {
        if (mode != MaskMode.TAIL) {
            this.fixedTailorSize = fixedTailorSize;
        }
    }

    @Override
    public String toString() {
        return "DesensitizerImpl{" +
                "mode=" + mode +
                ", fixedHeaderSize=" + fixedHeaderSize +
                ", fixedTailorSize=" + fixedTailorSize +
                ", maskChar='" + maskChar + '\'' +
                '}';
    }

    /**
     * 脱敏
     *
     * @param rawString
     * @return
     */
    @Override
    public String desensitize(String rawString) {
        if (Strings.isNullOrEmpty(rawString) || rawString.length() == 1) {
            return rawString;
        }
        if (this.auto) {
            return this.desensitizeAuto(rawString);
        }
        return this.desensitizeManual(rawString);
    }

    /**
     * 自动模式
     *
     * @param rawString
     * @return
     */
    private String desensitizeAuto(String rawString) {
        StringBuilder resultBuilder = new StringBuilder();
        int length = rawString.length();
        if (mode == MaskMode.TAIL || mode == MaskMode.HEAD) {
            // 以1/2作为遮挡范围
            int half = (int) Math.ceil(length / 2.0);
            boolean head = mode == MaskMode.HEAD;
            if (head) {
                resultBuilder.append(Strings.repeat(maskChar, half))
                        .append(rawString, half, length);
            } else {
                resultBuilder.append(rawString, 0, length - half)
                        .append(Strings.repeat(maskChar, half));
            }
            return resultBuilder.toString();
        }
        // 仅有两个字符，不能采用遮挡中间的做法
        if (length == 2) {
            return resultBuilder.append(rawString, 0, 1)
                    .append(maskChar).toString();
        }
        // 以一半字符被mask作为目标
        int middle = Math.max((int) Math.ceil(length / 2.0), 1);
        // 计算首尾字符长度
        int side = Math.max((int) Math.floor((length - middle) / 2.0), 1);
        // 修正中间被mask的长度
        middle = length - side * 2;
        resultBuilder.append(rawString, 0, side)
                .append(Strings.repeat(maskChar, middle))
                .append(rawString, side + middle, length);
        return resultBuilder.toString();
    }

    /**
     * 手动模式
     *
     * @param rawString
     * @return
     */
    private String desensitizeManual(String rawString) {
        StringBuilder resultBuilder = new StringBuilder();
        int length = rawString.length();
        int maskLength;
        switch (mode) {
            case TAIL:
                if (length <= fixedHeaderSize) {
                    return rawString;
                }
                maskLength = length - fixedHeaderSize;
                resultBuilder.append(rawString, 0, fixedHeaderSize)
                        .append(Strings.repeat(maskChar, maskLength));
                break;
            default:
            case HEAD:
                if (length <= fixedTailorSize) {
                    return rawString;
                }
                maskLength = length - fixedTailorSize;
                resultBuilder.append(Strings.repeat(maskChar, maskLength))
                        .append(rawString.substring(maskLength));
                break;
            case MIDDLE:
                int unmaskLength = fixedTailorSize + fixedHeaderSize;
                if (length <= unmaskLength) {
                    return rawString;
                }
                maskLength = length - unmaskLength;
                resultBuilder.append(rawString, 0, fixedHeaderSize)
                        .append(Strings.repeat(maskChar, maskLength))
                        .append(rawString, fixedHeaderSize + maskLength, length);
                break;
        }
        return resultBuilder.toString();
    }
}
