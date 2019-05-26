package com.stableforever.security.masking.config;

import com.stableforever.security.masking.Desensitizer;
import lombok.Data;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

/**
 * 配置属性
 *
 * @author colin
 * @version 0.1
 */
@Data
public class DesensitizerConfigProperties {
    /**
     * 是否启用
     */
    private boolean enabled = true;
    /**
     * 需要处理类名前缀
     */
    @NotNull
    private String classNamePrefix = "";
    /**
     * 中文人名的脱敏方式
     */
    @NotNull
    private Desensitizer.MaskMode chineseNameMaskMode = Desensitizer.MaskMode.MIDDLE;
    /**
     * 中文人名固定不变部分自动化处理
     */
    private boolean chineseNameFixedPartAutoDecide = true;
    /**
     * 中文人名脱敏时，固定不变部分的长度
     */
    @Min(1)
    private int chineseNameHeadSize = 1;

    /**
     * 中文人名的脱敏方式
     */
    @NotNull
    private Desensitizer.MaskMode idCardMaskMode = Desensitizer.MaskMode.MIDDLE;
    /**
     * 身份证号脱敏时，固定不变的首尾部份是否自动计算
     */
    private boolean idCardFixedPartAutoDecide = true;
    /**
     * 身份证号脱敏时，固定的头部长度
     */
    @Min(1)
    private int idCardFixedHeadSize = 3;
    /**
     * 身份证号脱敏时，固定的尾部长度
     */
    @Min(1)
    private int idCardFixedTailSize = 4;
    /**
     * 电话号码的脱敏方式
     */
    @NotNull
    private Desensitizer.MaskMode phoneNumberMaskMode = Desensitizer.MaskMode.MIDDLE;
    /**
     * 电话号码脱敏时，固定不变的首尾部份是否自动计算
     */
    private boolean phoneNumberFixedPartAutoDecide = true;
    /**
     * 电话号码脱敏时，固定的头部长度
     */
    @Min(1)
    private int phoneNumberFixedHeadSize = 3;
    /**
     * 电话号码脱敏时，固定的尾部长度
     */
    @Min(1)
    private int phoneNumberFixedTailSize = 4;
    /**
     * 地址脱敏方式
     */
    @NotNull
    private Desensitizer.MaskMode addressMaskMode = Desensitizer.MaskMode.MIDDLE;
    /**
     * 地址脱敏时，固定不变的首尾部份是否自动计算
     */
    private boolean addressFixedPartAutoDecide = true;
    /**
     * 地址脱敏时，固定的头部长度
     */
    @Min(1)
    private int addressFixedHeadSize = 6;
    /**
     * 地址脱敏时，固定的尾部长度
     */
    @Min(1)
    private int addressFixedTailSize = 6;
    /**
     * 地址脱敏方式
     */
    @NotNull
    private Desensitizer.MaskMode emailMaskMode = Desensitizer.MaskMode.MIDDLE;
    /**
     * 地址脱敏时，固定不变的首尾部份是否自动计算
     */
    private boolean emailFixedPartAutoDecide = true;
    /**
     * 地址脱敏时，固定的头部长度
     */
    @Min(1)
    private int emailFixedHeadSize = 2;
    /**
     * 地址脱敏时，固定的尾部长度
     */
    @Min(1)
    private int emailFixedTailSize = 2;
    /**
     * 银行卡脱敏方式
     */
    @NotNull
    private Desensitizer.MaskMode bankCardMaskMode = Desensitizer.MaskMode.MIDDLE;
    /**
     * 银行卡脱敏时，固定不变的首尾部份是否自动计算
     */
    private boolean bankCardFixedPartAutoDecide = true;
    /**
     * 银行卡脱敏时，固定的头部长度
     */
    @Min(1)
    private int bankCardFixedHeadSize = 4;
    /**
     * 银行卡脱敏时，固定的尾部长度
     */
    @Min(1)
    private int bankCardFixedTailSize = 4;
    /**
     * 普通数据脱敏方式
     */
    @NotNull
    private Desensitizer.MaskMode genericMaskMode = Desensitizer.MaskMode.MIDDLE;
    /**
     * 普通数据脱敏时，固定不变的首尾部份是否自动计算
     */
    private boolean genericFixedPartAutoDecide = true;
    /**
     * 普通数据脱敏时，固定的头部长度
     */
    @Min(1)
    private int genericFixedHeadSize = 4;
    /**
     * 普通数据脱敏时，固定的尾部长度
     */
    @Min(1)
    private int genericFixedTailSize = 4;
}
