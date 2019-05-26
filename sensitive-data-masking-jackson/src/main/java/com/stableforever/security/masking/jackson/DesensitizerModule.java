package com.stableforever.security.masking.jackson;

import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.BeanSerializerModifier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

/**
 * Jackson数据脱敏的模块
 *
 * @author colin
 * @version 0.1
 */
@Slf4j
public class DesensitizerModule extends SimpleModule {
    @Autowired
    public DesensitizerModule(ObjectMapper objectMapper, JsonStringDesensitizer jsonStringDesensitizer) {
        //添加modifier，并向objectmapper注册
        this.setSerializerModifier(new BeanSerializerModifierImpl(jsonStringDesensitizer));
        objectMapper.registerModule(this);
        log.info("Registering {} to object mapper", this.getClass());
    }

    private static class BeanSerializerModifierImpl extends BeanSerializerModifier {
        private JsonStringDesensitizer jsonStringDesensitizer;

        private BeanSerializerModifierImpl(JsonStringDesensitizer jsonStringDesensitizer) {
            this.jsonStringDesensitizer = jsonStringDesensitizer;
        }

        @Override
        public List<BeanPropertyWriter> changeProperties(SerializationConfig config, BeanDescription beanDesc, List<BeanPropertyWriter> beanProperties) {
            int length = beanProperties.size();
            // 修改BeanPropertyWriter
            for (int i = 0; i < length; i++) {
                BeanPropertyWriter oldWriter = beanProperties.get(i);
                beanProperties.set(i, new CustomBeanPropertyWriter(oldWriter, oldWriter.getName(), jsonStringDesensitizer));
            }
            return super.changeProperties(config, beanDesc, beanProperties);
        }
    }
}
