package com.reveny.devicecheck;

public final class Native {
    static {
        System.loadLibrary("devicecheck");
    }

    public static native byte[] getBytes(android.content.Context context, byte[] challenge);

    static native String getAppKey();

    static native long beginSensorCapture();

    static native void pushSensorEvent(long handle, int type, long timestamp, float[] values);

    static native byte[] finishSensorCapture(long handle);
}
