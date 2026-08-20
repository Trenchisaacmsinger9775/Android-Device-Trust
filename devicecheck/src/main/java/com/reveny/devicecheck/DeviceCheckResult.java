package com.reveny.devicecheck;

import org.json.JSONObject;

public final class DeviceCheckResult {
    private final String displayNonce;
    private final String displayDeviceId;
    private final String displayClusterId;
    private final String environmentStatus;
    private final String environmentTitle;
    private final String environmentMessage;
    private final boolean knownDevice;

    DeviceCheckResult(JSONObject json) {
        JSONObject displayIdentity = json.optJSONObject("display_identity");
        displayNonce = value(displayIdentity, "nonce");
        displayDeviceId = value(displayIdentity, "device_id");
        displayClusterId = value(displayIdentity, "cluster_id");

        JSONObject environment = json.optJSONObject("environment");
        environmentStatus = value(environment, "status", "normal");
        environmentTitle = value(environment, "title", "Device verified");
        environmentMessage = value(environment, "message", "No emulator or modification signal was reported.");

        JSONObject recognition = json.optJSONObject("recognition");
        knownDevice = recognition != null && recognition.optBoolean("known_device", false);
    }

    public String getDisplayNonce() {
        return displayNonce;
    }

    public String getDisplayDeviceId() {
        return displayDeviceId;
    }

    public String getDisplayClusterId() {
        return displayClusterId;
    }

    public String getEnvironmentStatus() {
        return environmentStatus;
    }

    public String getEnvironmentTitle() {
        return environmentTitle;
    }

    public String getEnvironmentMessage() {
        return environmentMessage;
    }

    public boolean isKnownDevice() {
        return knownDevice;
    }

    private static String value(JSONObject json, String name) {
        if (json == null || json.isNull(name)) return "";
        return json.optString(name, "");
    }

    private static String value(JSONObject json, String name, String fallback) {
        String result = value(json, name);
        return result.isEmpty() ? fallback : result;
    }
}
