package com.reveny.devicecheck;

import android.content.Context;
import android.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

public final class DeviceCheckClient {
    private static final String SERVER_BASE_URL = "https://api.reveny.me/v1";
    private static final String CHALLENGE_URL = SERVER_BASE_URL + "/challenge";
    private static final String CHECK_URL = SERVER_BASE_URL + "/check";
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private final OkHttpClient httpClient;

    public DeviceCheckClient() {
        this(new OkHttpClient.Builder()
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .callTimeout(12, TimeUnit.SECONDS)
                .build());
    }

    DeviceCheckClient(OkHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public DeviceCheckResult check(Context context, String appVersion) throws IOException, JSONException {
        byte[] challenge = fetchChallenge();
        byte[] nativeBytes = Native.getBytes(context.getApplicationContext(), challenge);
        if (nativeBytes.length == 0) {
            throw new IOException("Native package validation failed.");
        }
        return sendCheckRequest(nativeBytes, appVersion);
    }

    private byte[] fetchChallenge() throws IOException, JSONException {
        Request request = new Request.Builder()
                .url(CHALLENGE_URL)
                .get()
                .header("Accept", "application/json")
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            String body = body(response);
            if (!response.isSuccessful()) {
                throw new IOException("Server returned HTTP " + response.code() + " during challenge.");
            }
            String challenge = new JSONObject(body).getString("challenge");
            return Base64.decode(challenge, Base64.DEFAULT);
        }
    }

    private DeviceCheckResult sendCheckRequest(byte[] nativeBytes, String appVersion) throws IOException, JSONException {
        JSONObject requestJson = new JSONObject()
                .put("app_version", appVersion)
                .put("time", System.currentTimeMillis())
                .put("attestation", Base64.encodeToString(nativeBytes, Base64.NO_WRAP));

        RequestBody requestBody = RequestBody.create(requestJson.toString(), JSON);
        Request request = new Request.Builder()
                .url(CHECK_URL)
                .post(requestBody)
                .header("Accept", "application/json")
                .header("X-App-Key", Native.getAppKey())
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            String body = body(response);
            if (!response.isSuccessful()) {
                throw new IOException("Server returned HTTP " + response.code() + " during check.");
            }
            return new DeviceCheckResult(new JSONObject(body));
        }
    }

    private static String body(Response response) throws IOException {
        ResponseBody responseBody = response.body();
        return responseBody != null ? responseBody.string() : "";
    }
}
