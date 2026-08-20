#include "FingerprintSignals.hpp"

#include "AttestationKeys.hpp"
#include "SignalIds.hpp"

#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <dirent.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <cstring>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

static bool ClearException(JNIEnv* env)
{
    if (env == nullptr || !env->ExceptionCheck()) return false;
    env->ExceptionClear();
    return true;
}

static jclass FindClass(JNIEnv* env, const char* name)
{
    if (env == nullptr) return nullptr;
    jclass clazz = env->FindClass(name);
    if (ClearException(env)) return nullptr;
    return clazz;
}

static jstring NewString(JNIEnv* env, const char* value)
{
    if (env == nullptr) return nullptr;
    jstring string = env->NewStringUTF(value);
    if (ClearException(env)) return nullptr;
    return string;
}

static std::string JStringToString(JNIEnv* env, jstring string)
{
    if (env == nullptr || string == nullptr) return std::string();
    const char* chars = env->GetStringUTFChars(string, nullptr);
    if (chars == nullptr || ClearException(env)) return std::string();
    std::string out(chars);
    env->ReleaseStringUTFChars(string, chars);
    return out;
}

static std::vector<uint8_t> FromByteArray(JNIEnv* env, jbyteArray array)
{
    if (env == nullptr || array == nullptr) return {};
    jsize length = env->GetArrayLength(array);
    if (ClearException(env) || length <= 0) return {};
    std::vector<uint8_t> bytes(static_cast<size_t>(length));
    env->GetByteArrayRegion(array, 0, length, reinterpret_cast<jbyte*>(bytes.data()));
    if (ClearException(env)) return {};
    return bytes;
}

static jobject CallObject(JNIEnv* env, jobject object, const char* name, const char* signature, jvalue* args = nullptr)
{
    if (env == nullptr || object == nullptr) return nullptr;
    jclass clazz = env->GetObjectClass(object);
    if (ClearException(env) || clazz == nullptr) return nullptr;
    jmethodID method = env->GetMethodID(clazz, name, signature);
    env->DeleteLocalRef(clazz);
    if (ClearException(env) || method == nullptr) return nullptr;
    jobject result = args == nullptr ? env->CallObjectMethod(object, method) : env->CallObjectMethodA(object, method, args);
    if (ClearException(env)) return nullptr;
    return result;
}

static jint CallInt(JNIEnv* env, jobject object, const char* name, const char* signature, jvalue* args = nullptr)
{
    if (env == nullptr || object == nullptr) return 0;
    jclass clazz = env->GetObjectClass(object);
    if (ClearException(env) || clazz == nullptr) return 0;
    jmethodID method = env->GetMethodID(clazz, name, signature);
    env->DeleteLocalRef(clazz);
    if (ClearException(env) || method == nullptr) return 0;
    jint result = args == nullptr ? env->CallIntMethod(object, method) : env->CallIntMethodA(object, method, args);
    if (ClearException(env)) return 0;
    return result;
}

static bool CallVoid(JNIEnv* env, jobject object, const char* name, const char* signature, jvalue* args = nullptr)
{
    if (env == nullptr || object == nullptr) return false;
    jclass clazz = env->GetObjectClass(object);
    if (ClearException(env) || clazz == nullptr) return false;
    jmethodID method = env->GetMethodID(clazz, name, signature);
    env->DeleteLocalRef(clazz);
    if (ClearException(env) || method == nullptr) return false;
    if (args == nullptr) env->CallVoidMethod(object, method);
    else env->CallVoidMethodA(object, method, args);
    return !ClearException(env);
}

static jlong CallStaticLong(JNIEnv* env, const char* className, const char* name, const char* signature)
{
    jclass clazz = FindClass(env, className);
    if (clazz == nullptr) return 0;
    jmethodID method = env->GetStaticMethodID(clazz, name, signature);
    if (ClearException(env) || method == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return 0;
    }
    jlong result = env->CallStaticLongMethod(clazz, method);
    if (ClearException(env)) result = 0;
    env->DeleteLocalRef(clazz);
    return result;
}

static std::string ObjectToString(JNIEnv* env, jobject object)
{
    auto string = static_cast<jstring>(CallObject(env, object, "toString", "()Ljava/lang/String;"));
    std::string out = JStringToString(env, string);
    if (string != nullptr) env->DeleteLocalRef(string);
    return out;
}

static jobject GetSystemService(JNIEnv* env, jobject context, const char* service)
{
    jstring name = NewString(env, service);
    if (name == nullptr) return nullptr;
    jvalue args[1];
    args[0].l = name;
    jobject result = CallObject(env, context, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;", args);
    env->DeleteLocalRef(name);
    return result;
}

static jobject GetContentResolver(JNIEnv* env, jobject context)
{
    return CallObject(env, context, "getContentResolver", "()Landroid/content/ContentResolver;");
}

static std::string GetPackageName(JNIEnv* env, jobject context)
{
    auto package = static_cast<jstring>(CallObject(env, context, "getPackageName", "()Ljava/lang/String;"));
    std::string out = JStringToString(env, package);
    if (package != nullptr) env->DeleteLocalRef(package);
    return out;
}

static jobject GetPackageInfo(JNIEnv* env, jobject context, const std::string& packageName)
{
    jobject packageManager = CallObject(env, context, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    if (packageManager == nullptr || packageName.empty()) return nullptr;
    jstring name = NewString(env, packageName.c_str());
    if (name == nullptr)
    {
        env->DeleteLocalRef(packageManager);
        return nullptr;
    }
    jvalue args[2];
    args[0].l = name;
    args[1].i = 0;
    jobject info = CallObject(env, packageManager, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;", args);
    env->DeleteLocalRef(name);
    env->DeleteLocalRef(packageManager);
    return info;
}

static uint64_t GetPackageLongField(JNIEnv* env, jobject packageInfo, const char* name)
{
    if (packageInfo == nullptr) return 0;
    jclass clazz = env->GetObjectClass(packageInfo);
    if (ClearException(env) || clazz == nullptr) return 0;
    jfieldID field = env->GetFieldID(clazz, name, "J");
    if (ClearException(env) || field == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return 0;
    }
    jlong value = env->GetLongField(packageInfo, field);
    env->DeleteLocalRef(clazz);
    return value > 0 ? static_cast<uint64_t>(value) : 0;
}

static uint64_t GetPackageTime(JNIEnv* env, jobject context, const std::string& packageName, const char* field)
{
    jobject info = GetPackageInfo(env, context, packageName);
    uint64_t time = GetPackageLongField(env, info, field);
    if (info != nullptr) env->DeleteLocalRef(info);
    return time;
}

static int64_t ReadGlobalInt(JNIEnv* env, jobject context, const char* name, int defaultValue)
{
    jobject resolver = GetContentResolver(env, context);
    jclass globalClass = FindClass(env, "android/provider/Settings$Global");
    jstring key = NewString(env, name);
    if (resolver == nullptr || globalClass == nullptr || key == nullptr) return defaultValue;

    jmethodID method = env->GetStaticMethodID(globalClass, "getInt", "(Landroid/content/ContentResolver;Ljava/lang/String;I)I");
    if (ClearException(env) || method == nullptr)
    {
        env->DeleteLocalRef(key);
        env->DeleteLocalRef(globalClass);
        env->DeleteLocalRef(resolver);
        return defaultValue;
    }
    jint value = env->CallStaticIntMethod(globalClass, method, resolver, key, defaultValue);
    if (ClearException(env)) value = defaultValue;
    env->DeleteLocalRef(key);
    env->DeleteLocalRef(globalClass);
    env->DeleteLocalRef(resolver);
    return static_cast<int64_t>(value);
}

static std::string ReadSettingString(JNIEnv* env, jobject resolver, const char* className, const char* name)
{
    jclass clazz = FindClass(env, className);
    jstring key = NewString(env, name);
    if (clazz == nullptr || key == nullptr) return std::string();

    jmethodID method = env->GetStaticMethodID(clazz, "getString", "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
    if (ClearException(env) || method == nullptr)
    {
        env->DeleteLocalRef(key);
        env->DeleteLocalRef(clazz);
        return std::string();
    }
    auto value = static_cast<jstring>(env->CallStaticObjectMethod(clazz, method, resolver, key));
    if (ClearException(env)) value = nullptr;
    std::string out = JStringToString(env, value);
    if (value != nullptr) env->DeleteLocalRef(value);
    env->DeleteLocalRef(key);
    env->DeleteLocalRef(clazz);
    return out;
}

static void AddPackageTimeline(JNIEnv* env, jobject context, Protocol::Builder& protocol)
{
    Protocol::Builder timeline = Protocol::Create();
    std::string self = GetPackageName(env, context);
    timeline.AddUInt64(SignalIds::FP_ANDROID_FIRST_INSTALL_MS, GetPackageTime(env, context, "android", "firstInstallTime"));
    timeline.AddUInt64(SignalIds::FP_GMS_FIRST_INSTALL_MS, GetPackageTime(env, context, "com.google.android.gms", "firstInstallTime"));
    timeline.AddUInt64(SignalIds::FP_GMS_LAST_UPDATE_MS, GetPackageTime(env, context, "com.google.android.gms", "lastUpdateTime"));
    timeline.AddUInt64(SignalIds::FP_VENDING_FIRST_INSTALL_MS, GetPackageTime(env, context, "com.android.vending", "firstInstallTime"));
    timeline.AddUInt64(SignalIds::FP_SELF_FIRST_INSTALL_MS, GetPackageTime(env, context, self, "firstInstallTime"));
    timeline.AddUInt64(SignalIds::FP_SELF_LAST_UPDATE_MS, GetPackageTime(env, context, self, "lastUpdateTime"));
    timeline.AddInt64(SignalIds::FP_BOOT_COUNT, ReadGlobalInt(env, context, "boot_count", -1));

    int64_t nowMs = CallStaticLong(env, "java/lang/System", "currentTimeMillis", "()J");
    int64_t elapsedMs = CallStaticLong(env, "android/os/SystemClock", "elapsedRealtime", "()J");
    timeline.AddUInt64(SignalIds::FP_ELAPSED_REALTIME_MS, elapsedMs > 0 ? static_cast<uint64_t>(elapsedMs) : 0);
    timeline.AddUInt64(SignalIds::FP_BOOT_WALL_MS, nowMs > elapsedMs ? static_cast<uint64_t>(nowMs - elapsedMs) : 0);
    protocol.AddNested(SignalIds::FP_TIMELINE, timeline);
}

static void AddWidevine(JNIEnv* env, Protocol::Builder& protocol)
{
    jclass uuidClass = FindClass(env, "java/util/UUID");
    jclass mediaDrmClass = FindClass(env, "android/media/MediaDrm");
    if (uuidClass == nullptr || mediaDrmClass == nullptr) return;

    jmethodID uuidCtor = env->GetMethodID(uuidClass, "<init>", "(JJ)V");
    jmethodID drmCtor = env->GetMethodID(mediaDrmClass, "<init>", "(Ljava/util/UUID;)V");
    if (ClearException(env) || uuidCtor == nullptr || drmCtor == nullptr)
    {
        env->DeleteLocalRef(uuidClass);
        env->DeleteLocalRef(mediaDrmClass);
        return;
    }

    jobject uuid = env->NewObject(uuidClass, uuidCtor, static_cast<jlong>(0xEDEF8BA979D64ACEULL), static_cast<jlong>(0xA3C827DCD51D21EDULL));
    jobject mediaDrm = uuid != nullptr ? env->NewObject(mediaDrmClass, drmCtor, uuid) : nullptr;
    if (ClearException(env) || mediaDrm == nullptr)
    {
        if (uuid != nullptr) env->DeleteLocalRef(uuid);
        env->DeleteLocalRef(uuidClass);
        env->DeleteLocalRef(mediaDrmClass);
        return;
    }

    jstring deviceIdName = NewString(env, "deviceUniqueId");
    jvalue idArgs[1];
    idArgs[0].l = deviceIdName;
    auto deviceId = static_cast<jbyteArray>(CallObject(env, mediaDrm, "getPropertyByteArray", "(Ljava/lang/String;)[B", idArgs));
    std::vector<uint8_t> bytes = FromByteArray(env, deviceId);
    if (!bytes.empty())
    {
        protocol.AddUInt64(SignalIds::FP_WIDEVINE_ID_HASH64, AttestationKeys::Hash64(bytes));
        protocol.AddUInt64(SignalIds::FP_WIDEVINE_ID_SIZE, static_cast<uint64_t>(bytes.size()));
    }

    jstring securityName = NewString(env, "securityLevel");
    jvalue securityArgs[1];
    securityArgs[0].l = securityName;
    auto security = static_cast<jstring>(CallObject(env, mediaDrm, "getPropertyString", "(Ljava/lang/String;)Ljava/lang/String;", securityArgs));
    protocol.AddString(SignalIds::FP_WIDEVINE_SECURITY_LEVEL, JStringToString(env, security));

    CallVoid(env, mediaDrm, "release", "()V");
    if (security != nullptr) env->DeleteLocalRef(security);
    if (securityName != nullptr) env->DeleteLocalRef(securityName);
    if (deviceId != nullptr) env->DeleteLocalRef(deviceId);
    if (deviceIdName != nullptr) env->DeleteLocalRef(deviceIdName);
    env->DeleteLocalRef(mediaDrm);
    env->DeleteLocalRef(uuid);
    env->DeleteLocalRef(uuidClass);
    env->DeleteLocalRef(mediaDrmClass);
}

static void AddStorageOne(Protocol::Builder& protocol, uint64_t fieldId, const char* path)
{
    struct statvfs stats{};
    if (statvfs(path, &stats) != 0) return;
    Protocol::Builder storage = Protocol::Create();
    storage.AddUInt64(SignalIds::FP_STORAGE_BLOCK_SIZE, static_cast<uint64_t>(stats.f_frsize));
    storage.AddUInt64(SignalIds::FP_STORAGE_BLOCK_COUNT, static_cast<uint64_t>(stats.f_blocks));
    storage.AddUInt64(SignalIds::FP_STORAGE_BLOCK_FREE, static_cast<uint64_t>(stats.f_bfree));
    protocol.AddNested(fieldId, storage);
}

static void AddStorage(JNIEnv* env, jobject context, Protocol::Builder& protocol)
{
    AddStorageOne(protocol, SignalIds::FP_STORAGE_DATA, "/data");
    AddStorageOne(protocol, SignalIds::FP_STORAGE_CACHE, "/cache");

    jvalue args[1];
    args[0].l = nullptr;
    jobject external = CallObject(env, context, "getExternalFilesDir", "(Ljava/lang/String;)Ljava/io/File;", args);
    auto path = static_cast<jstring>(CallObject(env, external, "getAbsolutePath", "()Ljava/lang/String;"));
    std::string externalPath = JStringToString(env, path);
    if (!externalPath.empty()) AddStorageOne(protocol, SignalIds::FP_STORAGE_EXTERNAL, externalPath.c_str());
    if (path != nullptr) env->DeleteLocalRef(path);
    if (external != nullptr) env->DeleteLocalRef(external);
}

static int GetIntentExtraInt(JNIEnv* env, jobject intent, const char* name, int defaultValue)
{
    jstring key = NewString(env, name);
    if (key == nullptr) return defaultValue;
    jvalue args[2];
    args[0].l = key;
    args[1].i = defaultValue;
    int value = CallInt(env, intent, "getIntExtra", "(Ljava/lang/String;I)I", args);
    env->DeleteLocalRef(key);
    return value;
}

static void AddBattery(JNIEnv* env, jobject context, Protocol::Builder& protocol)
{
    Protocol::Builder battery = Protocol::Create();
    jobject batteryManager = GetSystemService(env, context, "batterymanager");
    if (batteryManager != nullptr)
    {
        jvalue args[1];
        args[0].i = 1;
        battery.AddInt64(SignalIds::FP_BATTERY_CHARGE_COUNTER, CallInt(env, batteryManager, "getIntProperty", "(I)I", args));
        args[0].i = 4;
        battery.AddInt64(SignalIds::FP_BATTERY_CAPACITY, CallInt(env, batteryManager, "getIntProperty", "(I)I", args));
        env->DeleteLocalRef(batteryManager);
    }

    jclass intentFilterClass = FindClass(env, "android/content/IntentFilter");
    jstring action = NewString(env, "android.intent.action.BATTERY_CHANGED");
    jobject filter = nullptr;
    if (intentFilterClass != nullptr && action != nullptr)
    {
        jmethodID ctor = env->GetMethodID(intentFilterClass, "<init>", "(Ljava/lang/String;)V");
        if (!ClearException(env) && ctor != nullptr) filter = env->NewObject(intentFilterClass, ctor, action);
    }
    if (action != nullptr) env->DeleteLocalRef(action);
    if (intentFilterClass != nullptr) env->DeleteLocalRef(intentFilterClass);

    jvalue receiverArgs[2];
    receiverArgs[0].l = nullptr;
    receiverArgs[1].l = filter;
    jobject intent = CallObject(env, context, "registerReceiver", "(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;", receiverArgs);
    if (intent != nullptr)
    {
        battery.AddInt64(SignalIds::FP_BATTERY_LEVEL, GetIntentExtraInt(env, intent, "level", -1));
        battery.AddInt64(SignalIds::FP_BATTERY_SCALE, GetIntentExtraInt(env, intent, "scale", -1));
        battery.AddInt64(SignalIds::FP_BATTERY_VOLTAGE, GetIntentExtraInt(env, intent, "voltage", -1));
        battery.AddInt64(SignalIds::FP_BATTERY_TEMPERATURE, GetIntentExtraInt(env, intent, "temperature", -1));
        env->DeleteLocalRef(intent);
    }
    if (filter != nullptr) env->DeleteLocalRef(filter);
    protocol.AddNested(SignalIds::FP_BATTERY, battery);
}

static void AddSettings(JNIEnv* env, jobject context, Protocol::Builder& protocol)
{
    jobject resolver = GetContentResolver(env, context);
    if (resolver == nullptr) return;

    struct Item
    {
        const char* className;
        const char* name;
    };

    Item items[] = {
            {"android/provider/Settings$System", "font_scale"},
            {"android/provider/Settings$System", "screen_brightness"},
            {"android/provider/Settings$System", "screen_off_timeout"},
            {"android/provider/Settings$System", "accelerometer_rotation"},
            {"android/provider/Settings$System", "time_12_24"},
            {"android/provider/Settings$Global", "window_animation_scale"},
            {"android/provider/Settings$Global", "transition_animation_scale"},
            {"android/provider/Settings$Global", "animator_duration_scale"},
            {"android/provider/Settings$Global", "development_settings_enabled"},
            {"android/provider/Settings$Global", "adb_enabled"}
    };

    std::string out;
    for (const Item& item : items)
    {
        if (!out.empty()) out += "\n";
        out += item.name;
        out += "=";
        out += ReadSettingString(env, resolver, item.className, item.name);
    }
    env->DeleteLocalRef(resolver);
    std::vector<uint8_t> bytes(out.begin(), out.end());
    protocol.AddUInt64(SignalIds::FP_SETTINGS_HASH64, AttestationKeys::Hash64(bytes));
    protocol.AddUInt64(SignalIds::FP_SETTINGS_SIZE, static_cast<uint64_t>(bytes.size()));
}

static void AddTelephony(JNIEnv* env, jobject context, Protocol::Builder& protocol)
{
    jobject telephony = GetSystemService(env, context, "phone");
    if (telephony == nullptr) return;

    const char* methods[] = {
            "getNetworkOperator",
            "getNetworkOperatorName",
            "getSimOperator",
            "getSimCountryIso"
    };

    std::string out;
    for (const char* method : methods)
    {
        auto value = static_cast<jstring>(CallObject(env, telephony, method, "()Ljava/lang/String;"));
        if (!out.empty()) out += "\n";
        out += method;
        out += "=";
        out += JStringToString(env, value);
        if (value != nullptr) env->DeleteLocalRef(value);
    }
    if (!out.empty()) out += "\n";
    out += "phoneType=";
    out += std::to_string(CallInt(env, telephony, "getPhoneType", "()I"));
    env->DeleteLocalRef(telephony);

    std::vector<uint8_t> bytes(out.begin(), out.end());
    protocol.AddUInt64(SignalIds::FP_TELEPHONY_HASH64, AttestationKeys::Hash64(bytes));
    protocol.AddUInt64(SignalIds::FP_TELEPHONY_SIZE, static_cast<uint64_t>(bytes.size()));
}

static uint64_t NowNs(clockid_t clock)
{
    timespec time{};
    if (clock_gettime(clock, &time) != 0) return 0;
    return static_cast<uint64_t>(time.tv_sec) * 1000000000ULL + static_cast<uint64_t>(time.tv_nsec);
}

static jobject GetCameraKey(JNIEnv* env, const char* name)
{
    jclass clazz = FindClass(env, "android/hardware/camera2/CameraCharacteristics");
    if (clazz == nullptr) return nullptr;
    jfieldID field = env->GetStaticFieldID(clazz, name, "Landroid/hardware/camera2/CameraCharacteristics$Key;");
    if (ClearException(env) || field == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return nullptr;
    }
    jobject key = env->GetStaticObjectField(clazz, field);
    if (ClearException(env)) key = nullptr;
    env->DeleteLocalRef(clazz);
    return key;
}

static jobject GetCameraValue(JNIEnv* env, jobject characteristics, const char* keyName)
{
    jobject key = GetCameraKey(env, keyName);
    if (key == nullptr) return nullptr;
    jvalue args[1];
    args[0].l = key;
    jobject value = CallObject(env, characteristics, "get", "(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;", args);
    env->DeleteLocalRef(key);
    return value;
}

static std::string IntArrayToString(JNIEnv* env, jintArray array)
{
    if (env == nullptr || array == nullptr) return std::string();
    jsize length = env->GetArrayLength(array);
    if (ClearException(env) || length <= 0) return std::string();
    std::vector<jint> values(static_cast<size_t>(length));
    env->GetIntArrayRegion(array, 0, length, values.data());
    if (ClearException(env)) return std::string();

    std::string out;
    for (jsize index = 0; index < length; ++index)
    {
        if (!out.empty()) out += ",";
        out += std::to_string(values[static_cast<size_t>(index)]);
    }
    return out;
}

static std::string FloatArrayToString(JNIEnv* env, jfloatArray array)
{
    if (env == nullptr || array == nullptr) return std::string();
    jsize length = env->GetArrayLength(array);
    if (ClearException(env) || length <= 0) return std::string();
    std::vector<jfloat> values(static_cast<size_t>(length));
    env->GetFloatArrayRegion(array, 0, length, values.data());
    if (ClearException(env)) return std::string();

    std::string out;
    for (jsize index = 0; index < length; ++index)
    {
        if (!out.empty()) out += ",";
        out += std::to_string(values[static_cast<size_t>(index)]);
    }
    return out;
}

static void AppendCameraObject(std::string& out, JNIEnv* env, jobject characteristics, const char* label, const char* keyName)
{
    jobject value = GetCameraValue(env, characteristics, keyName);
    out += label;
    out += "=";
    out += ObjectToString(env, value);
    out += "\n";
    if (value != nullptr) env->DeleteLocalRef(value);
}

static void AppendCameraIntArray(std::string& out, JNIEnv* env, jobject characteristics, const char* label, const char* keyName)
{
    auto value = static_cast<jintArray>(GetCameraValue(env, characteristics, keyName));
    out += label;
    out += "=";
    out += IntArrayToString(env, value);
    out += "\n";
    if (value != nullptr) env->DeleteLocalRef(value);
}

static void AppendCameraFloatArray(std::string& out, JNIEnv* env, jobject characteristics, const char* label, const char* keyName)
{
    auto value = static_cast<jfloatArray>(GetCameraValue(env, characteristics, keyName));
    out += label;
    out += "=";
    out += FloatArrayToString(env, value);
    out += "\n";
    if (value != nullptr) env->DeleteLocalRef(value);
}

static void AddCamera(JNIEnv* env, jobject context, Protocol::Builder& protocol)
{
    jobject cameraManager = GetSystemService(env, context, "camera");
    if (cameraManager == nullptr) return;

    auto ids = static_cast<jobjectArray>(CallObject(env, cameraManager, "getCameraIdList", "()[Ljava/lang/String;"));
    if (ids == nullptr)
    {
        env->DeleteLocalRef(cameraManager);
        return;
    }

    jsize count = env->GetArrayLength(ids);
    if (ClearException(env)) count = 0;

    std::string out = "count=" + std::to_string(count) + "\n";
    for (jsize index = 0; index < count; ++index)
    {
        auto id = static_cast<jstring>(env->GetObjectArrayElement(ids, index));
        if (ClearException(env) || id == nullptr) continue;
        std::string idString = JStringToString(env, id);
        jvalue args[1];
        args[0].l = id;
        jobject characteristics = CallObject(env, cameraManager, "getCameraCharacteristics", "(Ljava/lang/String;)Landroid/hardware/camera2/CameraCharacteristics;", args);
        env->DeleteLocalRef(id);
        if (characteristics == nullptr) continue;

        out += "camera=";
        out += idString;
        out += "\n";
        AppendCameraObject(out, env, characteristics, "sensor_physical_size", "SENSOR_INFO_PHYSICAL_SIZE");
        AppendCameraObject(out, env, characteristics, "pixel_array_size", "SENSOR_INFO_PIXEL_ARRAY_SIZE");
        AppendCameraObject(out, env, characteristics, "active_array_size", "SENSOR_INFO_ACTIVE_ARRAY_SIZE");
        AppendCameraObject(out, env, characteristics, "orientation", "SENSOR_ORIENTATION");
        AppendCameraObject(out, env, characteristics, "hardware_level", "INFO_SUPPORTED_HARDWARE_LEVEL");
        AppendCameraIntArray(out, env, characteristics, "capabilities", "REQUEST_AVAILABLE_CAPABILITIES");
        AppendCameraFloatArray(out, env, characteristics, "focal_lengths", "LENS_INFO_AVAILABLE_FOCAL_LENGTHS");
        env->DeleteLocalRef(characteristics);
    }

    env->DeleteLocalRef(ids);
    env->DeleteLocalRef(cameraManager);

    std::vector<uint8_t> bytes(out.begin(), out.end());
    protocol.AddUInt64(SignalIds::FP_CAMERA_COUNT, static_cast<uint64_t>(count));
    protocol.AddBytes(SignalIds::FP_CAMERA_CHARACTERISTICS_BLOB, bytes);
    protocol.AddUInt64(SignalIds::FP_CAMERA_CHARACTERISTICS_HASH64, AttestationKeys::Hash64(bytes));
    protocol.AddUInt64(SignalIds::FP_CAMERA_CHARACTERISTICS_SIZE, static_cast<uint64_t>(bytes.size()));
}

static GLuint CompileShader(GLenum type, const char* source)
{
    GLuint shader = glCreateShader(type);
    if (shader == 0) return 0;
    glShaderSource(shader, 1, &source, nullptr);
    glCompileShader(shader);
    GLint compiled = 0;
    glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
    if (compiled == GL_TRUE) return shader;
    glDeleteShader(shader);
    return 0;
}

static GLuint CreateTimingProgram()
{
    static constexpr const char* vertex =
            "attribute vec2 a;"
            "void main(){"
            "  gl_Position=vec4(a,0.0,1.0);"
            "}";
    static constexpr const char* fragment =
            "precision highp float;"
            "void main(){"
            "  float v=gl_FragCoord.x*0.017+gl_FragCoord.y*0.013;"
            "  for(int i=0;i<128;i++){v=sin(v)*cos(v)+sqrt(abs(v)+0.001);}"
            "  gl_FragColor=vec4(fract(v),fract(v*1.7),fract(v*2.3),1.0);"
            "}";

    GLuint vertexShader = CompileShader(GL_VERTEX_SHADER, vertex);
    GLuint fragmentShader = CompileShader(GL_FRAGMENT_SHADER, fragment);
    if (vertexShader == 0 || fragmentShader == 0)
    {
        if (vertexShader != 0) glDeleteShader(vertexShader);
        if (fragmentShader != 0) glDeleteShader(fragmentShader);
        return 0;
    }

    GLuint program = glCreateProgram();
    glAttachShader(program, vertexShader);
    glAttachShader(program, fragmentShader);
    glBindAttribLocation(program, 0, "a");
    glLinkProgram(program);
    glDeleteShader(vertexShader);
    glDeleteShader(fragmentShader);

    GLint linked = 0;
    glGetProgramiv(program, GL_LINK_STATUS, &linked);
    if (linked == GL_TRUE) return program;
    glDeleteProgram(program);
    return 0;
}

static void AddGpuTiming(Protocol::Builder& protocol)
{
    Protocol::Builder gpu = Protocol::Create();
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (display == EGL_NO_DISPLAY)
    {
        gpu.AddUInt64(SignalIds::FP_GPU_TIMING_STATUS, 1);
        protocol.AddNested(SignalIds::FP_GPU_TIMING, gpu);
        return;
    }

    EGLint major = 0;
    EGLint minor = 0;
    if (!eglInitialize(display, &major, &minor))
    {
        gpu.AddUInt64(SignalIds::FP_GPU_TIMING_STATUS, 2);
        protocol.AddNested(SignalIds::FP_GPU_TIMING, gpu);
        return;
    }

    EGLint configAttributes[] = {
            EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
            EGL_RED_SIZE, 8,
            EGL_GREEN_SIZE, 8,
            EGL_BLUE_SIZE, 8,
            EGL_NONE
    };
    EGLConfig config = nullptr;
    EGLint count = 0;
    if (!eglChooseConfig(display, configAttributes, &config, 1, &count) || count == 0)
    {
        eglTerminate(display);
        gpu.AddUInt64(SignalIds::FP_GPU_TIMING_STATUS, 3);
        protocol.AddNested(SignalIds::FP_GPU_TIMING, gpu);
        return;
    }

    EGLint surfaceAttributes[] = {EGL_WIDTH, 64, EGL_HEIGHT, 64, EGL_NONE};
    EGLSurface surface = eglCreatePbufferSurface(display, config, surfaceAttributes);
    EGLint contextAttributes[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, contextAttributes);
    if (surface == EGL_NO_SURFACE || context == EGL_NO_CONTEXT || !eglMakeCurrent(display, surface, surface, context))
    {
        if (surface != EGL_NO_SURFACE) eglDestroySurface(display, surface);
        if (context != EGL_NO_CONTEXT) eglDestroyContext(display, context);
        eglTerminate(display);
        gpu.AddUInt64(SignalIds::FP_GPU_TIMING_STATUS, 4);
        protocol.AddNested(SignalIds::FP_GPU_TIMING, gpu);
        return;
    }

    GLuint program = CreateTimingProgram();
    if (program == 0)
    {
        eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
        eglDestroySurface(display, surface);
        eglDestroyContext(display, context);
        eglTerminate(display);
        eglReleaseThread();
        gpu.AddUInt64(SignalIds::FP_GPU_TIMING_STATUS, 5);
        protocol.AddNested(SignalIds::FP_GPU_TIMING, gpu);
        return;
    }

    GLfloat vertices[] = {-1.0f, -1.0f, 1.0f, -1.0f, -1.0f, 1.0f, 1.0f, 1.0f};
    glViewport(0, 0, 64, 64);
    glUseProgram(program);
    glEnableVertexAttribArray(0);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, vertices);

    std::vector<uint8_t> samples;
    for (int sample = 0; sample < 12; ++sample)
    {
        uint64_t start = NowNs(CLOCK_MONOTONIC);
        for (int draw = 0; draw < 16; ++draw)
        {
            glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
        }
        glFinish();
        uint64_t end = NowNs(CLOCK_MONOTONIC);
        Protocol::AppendUInt64(samples, end > start ? end - start : 0);
    }

    glDisableVertexAttribArray(0);
    glDeleteProgram(program);
    eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroySurface(display, surface);
    eglDestroyContext(display, context);
    eglTerminate(display);
    eglReleaseThread();

    gpu.AddUInt64(SignalIds::FP_GPU_TIMING_STATUS, 0);
    gpu.AddBytes(SignalIds::FP_GPU_TIMING_SAMPLES, samples);
    gpu.AddUInt64(SignalIds::FP_GPU_TIMING_HASH64, AttestationKeys::Hash64(samples));
    protocol.AddNested(SignalIds::FP_GPU_TIMING, gpu);
}

static std::string ReadSmallFile(const std::string& path)
{
    std::ifstream file(path);
    if (!file) return std::string();
    std::string out;
    std::getline(file, out);
    return out;
}

static void AddThermalZones(Protocol::Builder& protocol)
{
    DIR* dir = opendir("/sys/clazz/thermal");
    if (dir == nullptr) return;

    std::string out;
    while (dirent* entry = readdir(dir))
    {
        std::string name = entry->d_name;
        if (name.find("thermal_zone") != 0) continue;
        std::string base = "/sys/clazz/thermal/" + name + "/";
        std::string type = ReadSmallFile(base + "type");
        std::string temp = ReadSmallFile(base + "temp");
        if (type.empty() || temp.empty()) continue;
        if (!out.empty()) out += "\n";
        out += name;
        out += "|";
        out += type;
        out += "|";
        out += temp;
    }
    closedir(dir);

    std::vector<uint8_t> bytes(out.begin(), out.end());
    protocol.AddBytes(SignalIds::FP_THERMAL_ZONES, bytes);
    protocol.AddUInt64(SignalIds::FP_THERMAL_ZONES_HASH64, AttestationKeys::Hash64(bytes));
    protocol.AddUInt64(SignalIds::FP_THERMAL_ZONES_SIZE, static_cast<uint64_t>(bytes.size()));
}

static void AddDisplayModes(JNIEnv* env, jobject context, Protocol::Builder& protocol)
{
    jobject displayManager = GetSystemService(env, context, "display");
    if (displayManager == nullptr) return;
    jvalue args[1];
    args[0].i = 0;
    jobject display = CallObject(env, displayManager, "getDisplay", "(I)Landroid/view/Display;", args);
    env->DeleteLocalRef(displayManager);
    if (display == nullptr) return;

    auto modes = static_cast<jobjectArray>(CallObject(env, display, "getSupportedModes", "()[Landroid/view/Display$Mode;"));
    std::string out;
    if (modes != nullptr)
    {
        jsize count = env->GetArrayLength(modes);
        if (ClearException(env)) count = 0;
        for (jsize index = 0; index < count; ++index)
        {
            jobject mode = env->GetObjectArrayElement(modes, index);
            if (ClearException(env) || mode == nullptr) continue;
            if (!out.empty()) out += "\n";
            out += ObjectToString(env, mode);
            env->DeleteLocalRef(mode);
        }
        env->DeleteLocalRef(modes);
    }

    jobject hdr = CallObject(env, display, "getHdrCapabilities", "()Landroid/view/Display$HdrCapabilities;");
    if (hdr != nullptr)
    {
        out += "\nhdr=";
        out += ObjectToString(env, hdr);
        env->DeleteLocalRef(hdr);
    }
    env->DeleteLocalRef(display);

    std::vector<uint8_t> bytes(out.begin(), out.end());
    protocol.AddUInt64(SignalIds::FP_DISPLAY_MODES_HASH64, AttestationKeys::Hash64(bytes));
    protocol.AddUInt64(SignalIds::FP_DISPLAY_MODES_SIZE, static_cast<uint64_t>(bytes.size()));
}

void FingerprintSignals::AddFingerprintSignals(JNIEnv* env, jobject context, Protocol::Builder& protocol)
{
    AddPackageTimeline(env, context, protocol);
    AddWidevine(env, protocol);
    AddStorage(env, context, protocol);
    AddBattery(env, context, protocol);
    AddSettings(env, context, protocol);
    AddTelephony(env, context, protocol);
    AddCamera(env, context, protocol);
    AddDisplayModes(env, context, protocol);
    AddGpuTiming(protocol);
    AddThermalZones(protocol);
}
