package com.stableforever.security.masking.jackson;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.impl.PropertySerializerMap;
import lombok.extern.slf4j.Slf4j;

/**
 * 定制化的属性writer
 *
 * @author colin
 * @version 0.1
 */
@Slf4j
public class CustomBeanPropertyWriter extends BeanPropertyWriter {
    /**
     * GETTER方法的前缀
     */
    private static final String GETTER_PREFIX = "get";
    private JsonStringDesensitizer jsonStringDesensitizer;

    CustomBeanPropertyWriter(BeanPropertyWriter base, String name, JsonStringDesensitizer jsonStringDesensitizer) {
        super(base, base.getFullName().withSimpleName(name));
        this.jsonStringDesensitizer = jsonStringDesensitizer;
    }

    @Override
    public void serializeAsField(Object bean, JsonGenerator gen, SerializerProvider prov) throws Exception {
        Class type = _accessorMethod == null ? _field.getDeclaringClass() : _accessorMethod.getDeclaringClass();
        String fieldName = null;
        if (_accessorMethod == null) {
            fieldName = _field.getName();
        } else if (_accessorMethod.getName().startsWith(GETTER_PREFIX)) {
            fieldName = _accessorMethod.getName().substring(GETTER_PREFIX.length());
            //首字母小写
            if (fieldName.length() >= 2) {
                fieldName = fieldName.substring(0, 1).toLowerCase() + fieldName.substring(1);
            } else {
                fieldName = fieldName.toLowerCase();
            }
        }
        final Object value = jsonStringDesensitizer.desensitive(
                (_accessorMethod == null) ? _field.get(bean) : _accessorMethod.invoke(bean, (Object[]) null),
                type,
                fieldName);
        // Null handling is bit different, check that first
        if (value == null) {
            if (_nullSerializer != null) {
                gen.writeFieldName(_name);
                _nullSerializer.serialize(null, gen, prov);
            }
            return;
        }
        // then find serializer to use
        JsonSerializer<Object> ser = _serializer;
        if (ser == null) {
            Class<?> cls = value.getClass();
            PropertySerializerMap m = _dynamicSerializers;
            ser = m.serializerFor(cls);
            if (ser == null) {
                ser = _findAndAddDynamic(m, cls, prov);
            }
        }
        // and then see if we must suppress certain values (default, empty)
        if (_suppressableValue != null) {
            if (MARKER_FOR_EMPTY == _suppressableValue) {
                if (ser.isEmpty(prov, value)) {
                    return;
                }
            } else if (_suppressableValue.equals(value)) {
                return;
            }
        }
        // For non-nulls: simple check for direct cycles
        if (value == bean) {
            // three choices: exception; handled by call; or pass-through
            if (_handleSelfReference(bean, gen, prov, ser)) {
                return;
            }
        }
        gen.writeFieldName(_name);
        if (_typeSerializer == null) {
            ser.serialize(value, gen, prov);
        } else {
            ser.serializeWithType(value, gen, prov, _typeSerializer);
        }
    }
}
