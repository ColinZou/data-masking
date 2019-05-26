package com.stableforever.security.masking.test;

import com.stableforever.security.masking.Sensitive;
import com.stableforever.security.masking.SensitiveType;
import lombok.Data;

@Data
public class SimpleModel {
    @Sensitive(value = SensitiveType.CHINESE_NAME)
    private String fullName;
}
