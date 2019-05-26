package com.stableforever.security.masking.jackson;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;

/**
 * 自动配置
 *
 * @author colin
 * @version 0.1
 */

@Configuration
@Slf4j
@EnableConfigurationProperties({JacksonDataMaskConfigProperties.class})
@ComponentScan("com.stableforever.security.masking")
public class DataMaskingSpringBootConfiguration {

    @Bean
    @Autowired
    public DesensitizerModule desensitizerModule(@Qualifier("jsonStringDesensitizer") JsonStringDesensitizer jsonStringDesensitizer,
                                                 ObjectMapper objectMapper, MappingJackson2HttpMessageConverter converter) {
        converter.setObjectMapper(objectMapper);
        log.info("INIT {} for desensitizing", DesensitizerModule.class);
        return new DesensitizerModule(objectMapper, jsonStringDesensitizer);
    }

    @Bean
    @Autowired
    public DesensitizerRegistry desensitizerRegistry(JacksonDataMaskConfigProperties properties) {
        return new DesensitizerRegistryImpl(properties);
    }

    @Bean
    @Autowired
    public JsonStringDesensitizer jsonStringDesensitizer(DesensitizerRegistry registry,
                                                         JacksonDataMaskConfigProperties properties) {
        return new JsonStringDesensitizerImpl(registry, properties.isEnabled(), properties.getClassNamePrefix());
    }

    @ConditionalOnMissingBean(type = {"org.springframework.http.converter.json.MappingJackson2HttpMessageConverter"})
    @Bean
    public MappingJackson2HttpMessageConverter converter() {
        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
        return converter;
    }

    @ConditionalOnMissingBean(type = {"com.fasterxml.jackson.databind.ObjectMapper"})
    @Bean
    public ObjectMapper jsonMapper() {
        return new ObjectMapper();
    }

}
