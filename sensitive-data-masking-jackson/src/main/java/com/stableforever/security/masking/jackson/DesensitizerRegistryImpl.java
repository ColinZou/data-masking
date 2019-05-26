package com.stableforever.security.masking.jackson;

import com.google.common.base.Strings;
import com.stableforever.security.masking.*;
import com.stableforever.security.masking.config.DesensitizerConfigProperties;

import java.lang.annotation.Annotation;
import java.util.HashMap;
import java.util.Map;

/**
 * 脱敏工具集
 *
 * @author colin
 * @version 0.1
 */
public class DesensitizerRegistryImpl implements DesensitizerRegistry {
    /**
     * 脱敏工具
     * map的key通过以下方法进行计算
     *
     * @link com.jiujin.json.desensitizer.service.DesensitizerRegistryImpl.SensitiveInstance#calcSensitiveHash()
     */
    private Map<Integer, Desensitizer> desensitizerMap = new HashMap<>();

    /**
     * 敏感对象实例，用于记录具体的脱敏配置
     *
     * @author colin
     * @version 0.1
     */
    @SuppressWarnings(value = "ALL")
    public static class SensitiveInstance implements Sensitive {
        private int hashCode;
        private final SensitiveType type;
        private final GenericMaskMode genericMaskMode;

        /**
         * 构造函数
         *
         * @param sensitive
         */
        SensitiveInstance(Sensitive sensitive) {
            this.type = sensitive.value();
            this.genericMaskMode = sensitive.numberMaskMode();
            this.hashCode = calcSensitiveHash(this.type, this.genericMaskMode);
        }

        /**
         * 构建函数
         *
         * @param type
         * @param genericMaskMode
         */
        SensitiveInstance(SensitiveType type, GenericMaskMode genericMaskMode) {
            this.type = type;
            this.genericMaskMode = genericMaskMode;
            this.hashCode = calcSensitiveHash(type, genericMaskMode);
        }

        SensitiveInstance(SensitiveType type) {
            this(type, GenericMaskMode.MIDDLE);
        }

        /**
         * 计算sensitive的hash值
         *
         * @param type
         * @param numberMaskMode
         * @return
         */
        static int calcSensitiveHash(SensitiveType type, GenericMaskMode numberMaskMode) {
            return type.hashCode() + numberMaskMode.hashCode();
        }

        @Override
        public int hashCode() {
            return this.hashCode;
        }

        @Override
        public boolean equals(Object obj) {
            if (null == obj || !Sensitive.class.isAssignableFrom(obj.getClass())) {
                return false;
            }
            Sensitive target = (Sensitive) obj;
            return target.value().equals(this.value()) &&
                    target.numberMaskMode().equals(this.numberMaskMode());
        }

        @Override
        public String toString() {
            return "SensitiveInstance{strValue='" + this.value().name() +
                    "' genericMaskMode='" + this.numberMaskMode().name() + "'}";
        }

        /**
         * 类型
         *
         * @return 类型
         */
        @Override
        public SensitiveType value() {
            return this.type;
        }

        /**
         * 一般的数字的mask模式
         *
         * @return
         */
        @Override
        public GenericMaskMode numberMaskMode() {
            return this.genericMaskMode;
        }

        /**
         * Returns the annotation type of this annotation.
         *
         * @return the annotation type of this annotation
         */
        @Override
        public Class<? extends Annotation> annotationType() {
            return Sensitive.class;
        }
    }

    /**
     * 电子邮件脱敏
     *
     * @author colin
     * @version 0.1
     */
    private static class EmailDesensitizer extends DesensitizerImpl {
        private static final String AT_SIGN = "@";

        EmailDesensitizer(final DesensitizerConfigProperties properties) {
            this.setMode(properties.getEmailMaskMode());
            this.setFixedHeaderSize(properties.getEmailFixedHeadSize());
            this.setFixedTailorSize(properties.getEmailFixedTailSize());
            this.setAuto(properties.isEmailFixedPartAutoDecide());
        }

        /**
         * 脱敏
         *
         * @param rawString
         * @return
         */
        @Override
        public String desensitize(final String rawString) {
            int atSignIndex = rawString.indexOf(AT_SIGN);
            if (atSignIndex <= 0) {
                return rawString;
            }
            return super.desensitize(rawString.substring(0, atSignIndex)) +
                    rawString.substring(atSignIndex);
        }
    }

    public DesensitizerRegistryImpl(final DesensitizerConfigProperties properties) {
        // 中文人名
        this.reg(new SensitiveInstance(SensitiveType.CHINESE_NAME),
                Desensitizer.builder()
                        .sethMode(properties.getChineseNameMaskMode())
                        .setFixedHeaderSize(properties.getChineseNameHeadSize())
                        .setAutoFixedPart(properties.isChineseNameFixedPartAutoDecide())
                        .build()
        );
        // 身份证号
        this.reg(new SensitiveInstance(SensitiveType.ID_CARD),
                Desensitizer.builder()
                        .sethMode(properties.getIdCardMaskMode())
                        .setFixedHeaderSize(properties.getIdCardFixedHeadSize())
                        .setFixedTailorSize(properties.getIdCardFixedTailSize())
                        .setAutoFixedPart(properties.isIdCardFixedPartAutoDecide())
                        .build()
        );
        //电话号码
        this.reg(new SensitiveInstance(SensitiveType.PHONE_NUMBER),
                Desensitizer.builder()
                        .sethMode(properties.getPhoneNumberMaskMode())
                        .setFixedHeaderSize(properties.getPhoneNumberFixedHeadSize())
                        .setFixedTailorSize(properties.getPhoneNumberFixedTailSize())
                        .setAutoFixedPart(properties.isPhoneNumberFixedPartAutoDecide())
                        .build()
        );
        // 地址
        this.reg(new SensitiveInstance(SensitiveType.ADDRESS),
                Desensitizer.builder()
                        .sethMode(properties.getAddressMaskMode())
                        .setFixedHeaderSize(properties.getAddressFixedHeadSize())
                        .setFixedTailorSize(properties.getAddressFixedTailSize())
                        .setAutoFixedPart(properties.isAddressFixedPartAutoDecide())
                        .build()
        );
        // 电子邮件
        this.reg(new SensitiveInstance(SensitiveType.EMAIL),
                new EmailDesensitizer(properties)
        );
        // 银行卡
        this.reg(new SensitiveInstance(SensitiveType.BANK_CARD),
                Desensitizer.builder()
                        .sethMode(properties.getBankCardMaskMode())
                        .setFixedHeaderSize(properties.getBankCardFixedHeadSize())
                        .setFixedTailorSize(properties.getBankCardFixedTailSize())
                        .setAutoFixedPart(properties.isBankCardFixedPartAutoDecide())
                        .build()
        );
        // 密码
        this.reg(new SensitiveInstance(SensitiveType.PASSWORD), rawString -> {
            if (Strings.isNullOrEmpty(rawString)) {
                return rawString;
            }
            return Strings.repeat(Desensitizer.DEFAULT_MASK_CHAR, rawString.length());
        });
        // 普通号码：头、中、后
        this.reg(new SensitiveInstance(SensitiveType.GENERIC, GenericMaskMode.HEAD),
                Desensitizer.builder()
                        .sethMode(Desensitizer.MaskMode.HEAD)
                        .setFixedHeaderSize(properties.getGenericFixedHeadSize())
                        .setFixedTailorSize(properties.getGenericFixedTailSize())
                        .setAutoFixedPart(properties.isGenericFixedPartAutoDecide())
                        .build()
        );
        this.reg(new SensitiveInstance(SensitiveType.GENERIC, GenericMaskMode.MIDDLE),
                Desensitizer.builder()
                        .sethMode(Desensitizer.MaskMode.MIDDLE)
                        .setFixedHeaderSize(properties.getGenericFixedHeadSize())
                        .setFixedTailorSize(properties.getGenericFixedTailSize())
                        .setAutoFixedPart(properties.isGenericFixedPartAutoDecide())
                        .build()
        );
        this.reg(new SensitiveInstance(SensitiveType.GENERIC, GenericMaskMode.TAIL),
                Desensitizer.builder()
                        .sethMode(Desensitizer.MaskMode.TAIL)
                        .setFixedHeaderSize(properties.getGenericFixedHeadSize())
                        .setFixedTailorSize(properties.getGenericFixedTailSize())
                        .setAutoFixedPart(properties.isGenericFixedPartAutoDecide())
                        .build()
        );
    }

    /**
     * 注册
     *
     * @param sensitive
     * @param item
     * @param item
     */
    void reg(Sensitive sensitive, Desensitizer item) {
        this.desensitizerMap.put(sensitive.hashCode(), item);
    }

    /**
     * 寻找实现
     *
     * @param sensitive
     * @return
     */
    @Override
    public Desensitizer lookup(Sensitive sensitive) {
        return desensitizerMap.get(SensitiveInstance.calcSensitiveHash(sensitive.value(), sensitive.numberMaskMode()));
    }
}
