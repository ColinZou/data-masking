package com.stableforever.security.masking.jackson;

import com.stableforever.security.masking.config.DesensitizerConfigProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "web.desensitizer")
public class JacksonDataMaskConfigProperties extends DesensitizerConfigProperties {
}
