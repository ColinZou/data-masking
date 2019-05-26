package com.stableforever.security.masking.test;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/v1/test")
public class TestController {
    @RequestMapping(produces = "application/json", method = RequestMethod.GET)
    public SimpleModel getSimpleModel() {
        SimpleModel model = new SimpleModel();
        model.setFullName("张小三");
        return model;
    }
}
