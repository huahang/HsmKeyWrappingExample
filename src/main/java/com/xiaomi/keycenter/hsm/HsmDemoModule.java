package com.xiaomi.keycenter.hsm;

import com.google.inject.AbstractModule;

/**
 * @author huahang
 */
public class HsmDemoModule extends AbstractModule {
    @Override
    protected void configure() {
        bind(DemoService.class).to(HsmDemoService.class);
    }
}
