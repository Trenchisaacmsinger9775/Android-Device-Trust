package com.reveny.devicecheck;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;

final class SensorBridge implements SensorEventListener {
    private final SensorManager sensorManager;
    private final long handle;

    private SensorBridge(SensorManager sensorManager, long handle) {
        this.sensorManager = sensorManager;
        this.handle = handle;
    }

    static byte[] collect(Context context) {
        SensorManager sensorManager = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
        if (sensorManager == null) return new byte[0];

        long handle = Native.beginSensorCapture();
        if (handle == 0L) return new byte[0];

        HandlerThread thread = new HandlerThread("sensor-bridge");
        thread.start();
        Handler handler = new Handler(thread.getLooper());
        SensorBridge bridge = new SensorBridge(sensorManager, handle);

        bridge.register(Sensor.TYPE_ACCELEROMETER, handler);
        bridge.register(Sensor.TYPE_GYROSCOPE_UNCALIBRATED, handler);
        bridge.register(Sensor.TYPE_MAGNETIC_FIELD_UNCALIBRATED, handler);
        bridge.register(Sensor.TYPE_ROTATION_VECTOR, handler);
        bridge.register(Sensor.TYPE_GAME_ROTATION_VECTOR, handler);
        SystemClock.sleep(500L);

        sensorManager.unregisterListener(bridge);
        thread.quitSafely();
        return Native.finishSensorCapture(handle);
    }

    private void register(int type, Handler handler) {
        Sensor sensor = sensorManager.getDefaultSensor(type);
        if (sensor == null) return;
        sensorManager.registerListener(this, sensor, SensorManager.SENSOR_DELAY_GAME, handler);
    }

    @Override
    public void onSensorChanged(SensorEvent event) {
        Native.pushSensorEvent(handle, event.sensor.getType(), event.timestamp, event.values);
    }

    @Override
    public void onAccuracyChanged(Sensor sensor, int accuracy) {
    }
}
