package com.stableforever.security.masking;

import org.junit.Assert;
import org.junit.Test;

/**
 * DesensitizerImpl的测试类
 * @author colin
 * @version 0.1
 */
public class DesensitizerImplTest {
    @Test
    public void testDesensitizeHeadModeManual() {
        Desensitizer headMode = Desensitizer.builder()
                .sethMode(Desensitizer.MaskMode.HEAD)
                .setFixedTailorSize(3).build();
        String raw = "123";
        String result = headMode.desensitize(raw);
        Assert.assertEquals(result, raw);

        raw = "1234";
        result = headMode.desensitize(raw);
        Assert.assertEquals("*234", result);

        raw = "13541355678";
        result = headMode.desensitize(raw);
        Assert.assertEquals("********678", result);
    }

    @Test
    public void testDesensitizeTailModeManual() {
        Desensitizer headMode = Desensitizer.builder()
                .sethMode(Desensitizer.MaskMode.TAIL)
                .setFixedHeaderSize(3).build();
        String raw = "123";
        String result = headMode.desensitize(raw);
        Assert.assertEquals(result, raw);

        raw = "1234";
        result = headMode.desensitize(raw);
        Assert.assertEquals("123*", result);

        raw = "13541355678";
        result = headMode.desensitize(raw);
        Assert.assertEquals("135********", result);
    }

    @Test
    public void testDesensitizeMiddleModeManual() {
        Desensitizer headMode = Desensitizer.builder()
                .sethMode(Desensitizer.MaskMode.MIDDLE)
                .setFixedHeaderSize(3).setFixedTailorSize(4).build();
        String raw = "123";
        String result = headMode.desensitize(raw);
        Assert.assertEquals(result, raw);

        raw = "1234";
        result = headMode.desensitize(raw);
        Assert.assertEquals("1234", result);

        raw = "12345678";
        result = headMode.desensitize(raw);
        Assert.assertEquals("123*5678", result);


        raw = "13541325678";
        result = headMode.desensitize(raw);
        Assert.assertEquals("135****5678", result);
    }

    @Test
    public void testDesensitizeHeadModeAuto() {
        Desensitizer headMode = Desensitizer.builder()
                .sethMode(Desensitizer.MaskMode.HEAD)
                .setAutoFixedPart(true).build();
        String raw = "1";
        String result = headMode.desensitize(raw);
        Assert.assertEquals(result, raw);

        raw = "12";
        result = headMode.desensitize(raw);
        Assert.assertEquals("*2", result);

        raw = "123";
        result = headMode.desensitize(raw);
        Assert.assertEquals("**3", result);

        raw = "1234";
        result = headMode.desensitize(raw);
        Assert.assertEquals("**34", result);

        raw = "12345";
        result = headMode.desensitize(raw);
        Assert.assertEquals("***45", result);
    }

    @Test
    public void testDesensitizeTailModeAuto() {
        Desensitizer headMode = Desensitizer.builder()
                .sethMode(Desensitizer.MaskMode.TAIL)
                .setAutoFixedPart(true).build();
        String raw = "123";
        String result = headMode.desensitize(raw);
        Assert.assertEquals("1**", result);

        raw = "1234";
        result = headMode.desensitize(raw);
        Assert.assertEquals("12**", result);

        raw = "12345";
        result = headMode.desensitize(raw);
        Assert.assertEquals("12***", result);
    }
    @Test
    public void testDesensitizeMiddleModeAuto() {
        Desensitizer headMode = Desensitizer.builder()
                .sethMode(Desensitizer.MaskMode.MIDDLE)
                .setAutoFixedPart(true).build();
        String raw = "123";
        String result = headMode.desensitize(raw);
        Assert.assertEquals("1*3", result);

        raw = "1234";
        result = headMode.desensitize(raw);
        Assert.assertEquals("1**4", result);

        raw = "12345678";
        result = headMode.desensitize(raw);
        Assert.assertEquals("12****78", result);


        raw = "13541325678";
        result = headMode.desensitize(raw);
        Assert.assertEquals("13*******78", result);
    }
}
