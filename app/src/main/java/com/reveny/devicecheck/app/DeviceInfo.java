package com.reveny.devicecheck.app;

import android.os.Build;

public final class DeviceInfo {
    private final String manufacturer;
    private final String model;
    private final String androidVersion;
    private final String kernelVersion;
    private final int sdk;
    private final String appVersion;

    private DeviceInfo(
            String manufacturer,
            String model,
            String androidVersion,
            String kernelVersion,
            int sdk,
            String appVersion) {
        this.manufacturer = manufacturer;
        this.model = model;
        this.androidVersion = androidVersion;
        this.kernelVersion = kernelVersion;
        this.sdk = sdk;
        this.appVersion = appVersion;
    }

    public static DeviceInfo collect(String appVersion) {
        return new DeviceInfo(
                Build.MANUFACTURER,
                Build.MODEL,
                Build.VERSION.RELEASE,
                System.getProperty("os.version", ""),
                Build.VERSION.SDK_INT,
                appVersion);
    }

    public String getManufacturer() {
        return manufacturer;
    }

    public String getModel() {
        return model;
    }

    public String getAndroidVersion() {
        return androidVersion;
    }

    public String getKernelVersion() {
        return kernelVersion;
    }

    public int getSdk() {
        return sdk;
    }

    public String getAppVersion() {
        return appVersion;
    }
}
