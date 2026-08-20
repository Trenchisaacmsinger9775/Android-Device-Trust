#include "FrameworkSignals.hpp"
#include "AttestationKeys.hpp"
#include "SignalIds.hpp"

#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <android/sensor.h>

#include <cstdio>
#include <string>
#include <vector>

static bool ClearException(JNIEnv* env)
{
    if (env == nullptr || !env->ExceptionCheck()) return false;

    env->ExceptionClear();
    return true;
}

static std::string JStringToString(JNIEnv* env, jstring string)
{
    if (env == nullptr || string == nullptr) return std::string();

    const char* chars = env->GetStringUTFChars(string, nullptr);
    if (chars == nullptr)
    {
        ClearException(env);
        return std::string();
    }

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

static std::string ObjectToString(JNIEnv* env, jobject object)
{
    if (env == nullptr || object == nullptr) return std::string();

    jclass clazz = env->GetObjectClass(object);
    if (ClearException(env) || clazz == nullptr) return std::string();

    jmethodID method = env->GetMethodID(clazz, "toString", "()Ljava/lang/String;");
    if (ClearException(env) || method == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return std::string();
    }

    jstring value = static_cast<jstring>(env->CallObjectMethod(object, method));
    if (ClearException(env) || value == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return std::string();
    }

    std::string out = JStringToString(env, value);
    env->DeleteLocalRef(value);
    env->DeleteLocalRef(clazz);
    return out;
}

static jclass FindClass(JNIEnv* env, const char* name)
{
    if (env == nullptr) return nullptr;

    jclass clazz = env->FindClass(name);
    if (ClearException(env)) return nullptr;
    return clazz;
}

static std::vector<uint8_t> CallStaticByteArray(JNIEnv* env, const char* className, const char* methodName, jobject context)
{
    jclass clazz = FindClass(env, className);
    if (clazz == nullptr) return {};

    jmethodID method = env->GetStaticMethodID(clazz, methodName, "(Landroid/content/Context;)[B");
    if (ClearException(env) || method == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return {};
    }

    auto array = static_cast<jbyteArray>(env->CallStaticObjectMethod(clazz, method, context));
    if (ClearException(env))
    {
        env->DeleteLocalRef(clazz);
        return {};
    }

    std::vector<uint8_t> bytes = FromByteArray(env, array);
    if (array != nullptr) env->DeleteLocalRef(array);
    env->DeleteLocalRef(clazz);
    return bytes;
}

static std::string GetStaticStringField(JNIEnv* env, const char* className, const char* fieldName)
{
    jclass clazz = FindClass(env, className);
    if (clazz == nullptr) return std::string();

    jfieldID field = env->GetStaticFieldID(clazz, fieldName, "Ljava/lang/String;");
    if (ClearException(env) || field == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return std::string();
    }

    jstring value = static_cast<jstring>(env->GetStaticObjectField(clazz, field));
    std::string out = JStringToString(env, value);
    if (value != nullptr) env->DeleteLocalRef(value);
    env->DeleteLocalRef(clazz);
    return out;
}

static int GetStaticIntField(JNIEnv* env, const char* className, const char* fieldName)
{
    jclass clazz = FindClass(env, className);
    if (clazz == nullptr) return 0;

    jfieldID field = env->GetStaticFieldID(clazz, fieldName, "I");
    if (ClearException(env) || field == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return 0;
    }

    jint value = env->GetStaticIntField(clazz, field);
    env->DeleteLocalRef(clazz);
    return static_cast<int>(value);
}

static std::vector<std::string> GetStaticStringArray(JNIEnv* env, const char* className, const char* fieldName)
{
    std::vector<std::string> out;
    jclass clazz = FindClass(env, className);
    if (clazz == nullptr) return out;

    jfieldID field = env->GetStaticFieldID(clazz, fieldName, "[Ljava/lang/String;");
    if (ClearException(env) || field == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return out;
    }

    jobjectArray array = static_cast<jobjectArray>(env->GetStaticObjectField(clazz, field));
    if (ClearException(env) || array == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return out;
    }

    jsize count = env->GetArrayLength(array);
    for (jsize index = 0; index < count; ++index)
    {
        jstring item = static_cast<jstring>(env->GetObjectArrayElement(array, index));
        if (ClearException(env) || item == nullptr) continue;

        out.push_back(JStringToString(env, item));
        env->DeleteLocalRef(item);
    }

    env->DeleteLocalRef(array);
    env->DeleteLocalRef(clazz);
    return out;
}

static jobject CallObject(JNIEnv* env, jobject object, const char* name, const char* signature)
{
    if (env == nullptr || object == nullptr) return nullptr;

    jclass clazz = env->GetObjectClass(object);
    if (ClearException(env) || clazz == nullptr) return nullptr;

    jmethodID method = env->GetMethodID(clazz, name, signature);
    if (ClearException(env) || method == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return nullptr;
    }

    jobject result = env->CallObjectMethod(object, method);
    ClearException(env);
    env->DeleteLocalRef(clazz);
    return result;
}

static jboolean CallBoolean(JNIEnv* env, jobject object, const char* name, const char* signature, jstring arg)
{
    if (env == nullptr || object == nullptr) return JNI_FALSE;

    jclass clazz = env->GetObjectClass(object);
    if (ClearException(env) || clazz == nullptr) return JNI_FALSE;

    jmethodID method = env->GetMethodID(clazz, name, signature);
    if (ClearException(env) || method == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return JNI_FALSE;
    }

    jboolean result = env->CallBooleanMethod(object, method, arg);
    if (ClearException(env)) result = JNI_FALSE;
    env->DeleteLocalRef(clazz);
    return result;
}

static std::string GetPackageName(JNIEnv* env, jobject context)
{
    jstring packageName = static_cast<jstring>(CallObject(env, context, "getPackageName", "()Ljava/lang/String;"));
    std::string out = JStringToString(env, packageName);
    if (packageName != nullptr) env->DeleteLocalRef(packageName);
    return out;
}

static jobject GetPackageManager(JNIEnv* env, jobject context)
{
    return CallObject(env, context, "getPackageManager", "()Landroid/content/pm/PackageManager;");
}

static std::string GetFilePath(JNIEnv* env, jobject file)
{
    if (file == nullptr) return std::string();

    jstring path = static_cast<jstring>(CallObject(env, file, "getAbsolutePath", "()Ljava/lang/String;"));
    std::string out = JStringToString(env, path);
    if (path != nullptr) env->DeleteLocalRef(path);
    return out;
}

static std::string GetApplicationInfoStringField(JNIEnv* env, jobject context, const char* fieldName)
{
    jobject info = CallObject(env, context, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
    if (info == nullptr) return std::string();

    jclass clazz = env->GetObjectClass(info);
    if (ClearException(env) || clazz == nullptr)
    {
        env->DeleteLocalRef(info);
        return std::string();
    }

    jfieldID field = env->GetFieldID(clazz, fieldName, "Ljava/lang/String;");
    if (ClearException(env) || field == nullptr)
    {
        env->DeleteLocalRef(clazz);
        env->DeleteLocalRef(info);
        return std::string();
    }

    jstring value = static_cast<jstring>(env->GetObjectField(info, field));
    std::string out = JStringToString(env, value);
    if (value != nullptr) env->DeleteLocalRef(value);
    env->DeleteLocalRef(clazz);
    env->DeleteLocalRef(info);
    return out;
}

static std::string GetInstallerPackageName(JNIEnv* env, jobject context, const std::string& packageName)
{
    jobject packageManager = GetPackageManager(env, context);
    if (packageManager == nullptr || packageName.empty()) return std::string();

    jclass clazz = env->GetObjectClass(packageManager);
    if (ClearException(env) || clazz == nullptr)
    {
        env->DeleteLocalRef(packageManager);
        return std::string();
    }

    jmethodID method = env->GetMethodID(clazz, "getInstallerPackageName", "(Ljava/lang/String;)Ljava/lang/String;");
    if (ClearException(env) || method == nullptr)
    {
        env->DeleteLocalRef(clazz);
        env->DeleteLocalRef(packageManager);
        return std::string();
    }

    jstring package = env->NewStringUTF(packageName.c_str());
    jstring installer = static_cast<jstring>(env->CallObjectMethod(packageManager, method, package));
    ClearException(env);
    std::string out = JStringToString(env, installer);
    if (installer != nullptr) env->DeleteLocalRef(installer);
    if (package != nullptr) env->DeleteLocalRef(package);
    env->DeleteLocalRef(clazz);
    env->DeleteLocalRef(packageManager);
    return out;
}

static std::string GetAppVersion(JNIEnv* env, jobject context, const std::string& packageName)
{
    jobject packageManager = GetPackageManager(env, context);
    if (packageManager == nullptr || packageName.empty()) return std::string();

    jclass clazz = env->GetObjectClass(packageManager);
    if (ClearException(env) || clazz == nullptr)
    {
        env->DeleteLocalRef(packageManager);
        return std::string();
    }

    jmethodID method = env->GetMethodID(clazz, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (ClearException(env) || method == nullptr)
    {
        env->DeleteLocalRef(clazz);
        env->DeleteLocalRef(packageManager);
        return std::string();
    }

    jstring package = env->NewStringUTF(packageName.c_str());
    jobject info = env->CallObjectMethod(packageManager, method, package, 0);
    ClearException(env);
    if (package != nullptr) env->DeleteLocalRef(package);
    env->DeleteLocalRef(clazz);
    env->DeleteLocalRef(packageManager);
    if (info == nullptr) return std::string();

    jclass infoClass = env->GetObjectClass(info);
    jfieldID field = infoClass != nullptr ? env->GetFieldID(infoClass, "versionName", "Ljava/lang/String;") : nullptr;
    if (ClearException(env) || field == nullptr)
    {
        if (infoClass != nullptr) env->DeleteLocalRef(infoClass);
        env->DeleteLocalRef(info);
        return std::string();
    }

    jstring value = static_cast<jstring>(env->GetObjectField(info, field));
    std::string out = JStringToString(env, value);
    if (value != nullptr) env->DeleteLocalRef(value);
    env->DeleteLocalRef(infoClass);
    env->DeleteLocalRef(info);
    return out;
}

static jobject GetPackageInfo(JNIEnv* env, jobject context, const std::string& packageName, int flags)
{
    jobject packageManager = GetPackageManager(env, context);
    if (packageManager == nullptr || packageName.empty()) return nullptr;

    jclass clazz = env->GetObjectClass(packageManager);
    if (ClearException(env) || clazz == nullptr)
    {
        env->DeleteLocalRef(packageManager);
        return nullptr;
    }

    jmethodID method = env->GetMethodID(clazz, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (ClearException(env) || method == nullptr)
    {
        env->DeleteLocalRef(clazz);
        env->DeleteLocalRef(packageManager);
        return nullptr;
    }

    jstring package = env->NewStringUTF(packageName.c_str());
    jobject info = env->CallObjectMethod(packageManager, method, package, flags);
    ClearException(env);
    if (package != nullptr) env->DeleteLocalRef(package);
    env->DeleteLocalRef(clazz);
    env->DeleteLocalRef(packageManager);
    return info;
}

static uint64_t GetAppSignersDigest64(JNIEnv* env, jobject context, const std::string& packageName)
{
    static constexpr int getSignatures = 64;

    jobject info = GetPackageInfo(env, context, packageName, getSignatures);
    if (info == nullptr) return 0;

    jclass infoClass = env->GetObjectClass(info);
    jfieldID field = infoClass != nullptr ? env->GetFieldID(infoClass, "signatures", "[Landroid/content/pm/Signature;") : nullptr;
    if (ClearException(env) || infoClass == nullptr || field == nullptr)
    {
        if (infoClass != nullptr) env->DeleteLocalRef(infoClass);
        env->DeleteLocalRef(info);
        return 0;
    }

    auto signatures = static_cast<jobjectArray>(env->GetObjectField(info, field));
    if (ClearException(env) || signatures == nullptr)
    {
        env->DeleteLocalRef(infoClass);
        env->DeleteLocalRef(info);
        return 0;
    }

    std::vector<uint8_t> bytes;
    jsize count = env->GetArrayLength(signatures);
    if (ClearException(env)) count = 0;
    for (jsize index = 0; index < count; ++index)
    {
        jobject signature = env->GetObjectArrayElement(signatures, index);
        if (ClearException(env) || signature == nullptr) continue;

        auto array = static_cast<jbyteArray>(CallObject(env, signature, "toByteArray", "()[B"));
        if (array != nullptr)
        {
            jsize length = env->GetArrayLength(array);
            if (!ClearException(env) && length > 0)
            {
                size_t offset = bytes.size();
                bytes.resize(offset + static_cast<size_t>(length));
                env->GetByteArrayRegion(array, 0, length, reinterpret_cast<jbyte*>(bytes.data() + offset));
                if (ClearException(env)) bytes.resize(offset);
            }
            env->DeleteLocalRef(array);
        }
        env->DeleteLocalRef(signature);
    }

    env->DeleteLocalRef(signatures);
    env->DeleteLocalRef(infoClass);
    env->DeleteLocalRef(info);
    return bytes.empty() ? 0 : AttestationKeys::Hash64(bytes);
}

static uint64_t IsPackagePresent(JNIEnv* env, jobject context, const std::string& packageName)
{
    jobject info = GetPackageInfo(env, context, packageName, 0);
    if (info == nullptr) return 0;
    env->DeleteLocalRef(info);
    return 1;
}

static std::string GetDisplayMetrics(JNIEnv* env, jobject context)
{
    jobject resources = CallObject(env, context, "getResources", "()Landroid/content/res/Resources;");
    if (resources == nullptr) return std::string();

    jobject metrics = CallObject(env, resources, "getDisplayMetrics", "()Landroid/util/DisplayMetrics;");
    env->DeleteLocalRef(resources);
    if (metrics == nullptr) return std::string();

    jclass clazz = env->GetObjectClass(metrics);
    if (ClearException(env) || clazz == nullptr)
    {
        env->DeleteLocalRef(metrics);
        return std::string();
    }

    jfieldID width = env->GetFieldID(clazz, "widthPixels", "I");
    jfieldID height = env->GetFieldID(clazz, "heightPixels", "I");
    jfieldID densityDpi = env->GetFieldID(clazz, "densityDpi", "I");
    jfieldID density = env->GetFieldID(clazz, "density", "F");
    if (ClearException(env) || width == nullptr || height == nullptr || densityDpi == nullptr || density == nullptr)
    {
        env->DeleteLocalRef(clazz);
        env->DeleteLocalRef(metrics);
        return std::string();
    }

    std::string out = std::to_string(env->GetIntField(metrics, width)) + "x" + std::to_string(env->GetIntField(metrics, height))
            + ";density=" + std::to_string(env->GetFloatField(metrics, density))
            + ";dpi=" + std::to_string(env->GetIntField(metrics, densityDpi));
    env->DeleteLocalRef(clazz);
    env->DeleteLocalRef(metrics);
    return out;
}

static std::string GetLocale(JNIEnv* env)
{
    jclass clazz = FindClass(env, "java/util/Locale");
    if (clazz == nullptr) return std::string();

    jmethodID defaultValue = env->GetStaticMethodID(clazz, "getDefault", "()Ljava/util/Locale;");
    if (ClearException(env) || defaultValue == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return std::string();
    }

    jobject locale = env->CallStaticObjectMethod(clazz, defaultValue);
    ClearException(env);
    std::string out = ObjectToString(env, locale);
    if (locale != nullptr) env->DeleteLocalRef(locale);
    env->DeleteLocalRef(clazz);
    return out;
}

static std::string GetTimezone(JNIEnv* env)
{
    jclass clazz = FindClass(env, "java/util/TimeZone");
    if (clazz == nullptr) return std::string();

    jmethodID defaultValue = env->GetStaticMethodID(clazz, "getDefault", "()Ljava/util/TimeZone;");
    if (ClearException(env) || defaultValue == nullptr)
    {
        env->DeleteLocalRef(clazz);
        return std::string();
    }

    jobject timezone = env->CallStaticObjectMethod(clazz, defaultValue);
    ClearException(env);
    jstring id = timezone != nullptr ? static_cast<jstring>(CallObject(env, timezone, "getID", "()Ljava/lang/String;")) : nullptr;
    std::string out = JStringToString(env, id);
    if (id != nullptr) env->DeleteLocalRef(id);
    if (timezone != nullptr) env->DeleteLocalRef(timezone);
    env->DeleteLocalRef(clazz);
    return out;
}

static std::string GetGlString(GLenum name)
{
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (display == EGL_NO_DISPLAY) return std::string();

    EGLint major = 0;
    EGLint minor = 0;
    if (!eglInitialize(display, &major, &minor)) return std::string();

    EGLint configAttributes[] = {
            EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
            EGL_NONE
    };
    EGLConfig config = nullptr;
    EGLint count = 0;
    if (!eglChooseConfig(display, configAttributes, &config, 1, &count) || count == 0)
    {
        eglTerminate(display);
        return std::string();
    }

    EGLint surfaceAttributes[] = {EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE};
    EGLSurface surface = eglCreatePbufferSurface(display, config, surfaceAttributes);
    EGLint contextAttributes[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, contextAttributes);
    if (surface == EGL_NO_SURFACE || context == EGL_NO_CONTEXT || !eglMakeCurrent(display, surface, surface, context))
    {
        if (surface != EGL_NO_SURFACE) eglDestroySurface(display, surface);
        if (context != EGL_NO_CONTEXT) eglDestroyContext(display, context);
        eglTerminate(display);
        return std::string();
    }

    const GLubyte* value = glGetString(name);
    std::string out = value != nullptr ? reinterpret_cast<const char*>(value) : "";
    eglMakeCurrent(display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroySurface(display, surface);
    eglDestroyContext(display, context);
    eglTerminate(display);
    eglReleaseThread();
    return out;
}

static jobject GetSensorManager(JNIEnv* env, jobject context)
{
    if (env == nullptr || context == nullptr) return nullptr;

    jstring service = env->NewStringUTF("sensor");
    jclass clazz = env->GetObjectClass(context);
    if (ClearException(env) || clazz == nullptr)
    {
        if (service != nullptr) env->DeleteLocalRef(service);
        return nullptr;
    }

    jmethodID method = env->GetMethodID(clazz, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;");
    if (ClearException(env) || method == nullptr)
    {
        if (service != nullptr) env->DeleteLocalRef(service);
        env->DeleteLocalRef(clazz);
        return nullptr;
    }

    jobject manager = env->CallObjectMethod(context, method, service);
    ClearException(env);
    if (service != nullptr) env->DeleteLocalRef(service);
    env->DeleteLocalRef(clazz);
    return manager;
}

static std::string CleanField(std::string value)
{
    for (char& character : value)
    {
        if (character == '\n' || character == '\r') character = ' ';
        else if (character == '|') character = '/';
    }
    return value;
}

static std::string FloatValue(float value)
{
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%.9g", value);
    return buffer;
}

static ASensorManager* GetNativeSensorManager()
{
    return ASensorManager_getInstance();
}

static std::string GetNativeSensorInventory(ASensorManager* sensorManager)
{
    if (sensorManager == nullptr) return std::string();

    ASensorList sensors = nullptr;
    int count = ASensorManager_getSensorList(sensorManager, &sensors);
    if (count <= 0 || sensors == nullptr) return std::string();

    std::string out;
    for (int index = 0; index < count; ++index)
    {
        const ASensor* sensor = sensors[index];
        if (sensor == nullptr) continue;
        if (!out.empty()) out += "\n";
        out += "sensor|";
        out += std::to_string(ASensor_getType(sensor));
        out += "|";
        out += CleanField(ASensor_getName(sensor) != nullptr ? ASensor_getName(sensor) : "");
        out += "|";
        out += CleanField(ASensor_getVendor(sensor) != nullptr ? ASensor_getVendor(sensor) : "");
        out += "|";
        out += std::to_string(ASensor_getMinDelay(sensor));
        out += "|";
        out += FloatValue(ASensor_getResolution(sensor));
        out += "|";
        out += std::to_string(ASensor_getFifoReservedEventCount(sensor));
        out += "|";
        out += std::to_string(ASensor_getFifoMaxEventCount(sensor));
        out += "|";
        out += (ASensor_isWakeUpSensor(sensor) ? "1" : "0");
        out += "|";
        out += std::to_string(ASensor_getReportingMode(sensor));
    }
    return out;
}

static int GetNativeSensorCount(ASensorManager* sensorManager)
{
    if (sensorManager == nullptr) return 0;
    ASensorList sensors = nullptr;
    int count = ASensorManager_getSensorList(sensorManager, &sensors);
    return count > 0 ? count : 0;
}

static std::string GetFeatureSensorPairs(JNIEnv* env, jobject context, jobject sensorManager)
{
    jobject packageManager = GetPackageManager(env, context);
    if (packageManager == nullptr || sensorManager == nullptr) return std::string();

    jclass sensorManagerClass = env->GetObjectClass(sensorManager);
    jmethodID getDefaultSensor = sensorManagerClass != nullptr ? env->GetMethodID(sensorManagerClass, "getDefaultSensor", "(I)Landroid/hardware/Sensor;") : nullptr;
    if (ClearException(env) || sensorManagerClass == nullptr || getDefaultSensor == nullptr)
    {
        if (sensorManagerClass != nullptr) env->DeleteLocalRef(sensorManagerClass);
        env->DeleteLocalRef(packageManager);
        return std::string();
    }

    struct Pair
    {
        const char* feature;
        int sensorType;
    };

    Pair pairs[] = {
            {"android.hardware.sensor.barometer", 6},
            {"android.hardware.sensor.gyroscope", 4},
            {"android.hardware.sensor.compass", 2},
            {"android.hardware.sensor.light", 5},
            {"android.hardware.sensor.proximity", 8}
    };

    std::string out;
    for (const Pair& pair : pairs)
    {
        jstring feature = env->NewStringUTF(pair.feature);
        bool hasFeature = CallBoolean(env, packageManager, "hasSystemFeature", "(Ljava/lang/String;)Z", feature) == JNI_TRUE;
        jobject sensor = env->CallObjectMethod(sensorManager, getDefaultSensor, pair.sensorType);
        bool hasSensor = !ClearException(env) && sensor != nullptr;
        if (sensor != nullptr) env->DeleteLocalRef(sensor);
        if (feature != nullptr) env->DeleteLocalRef(feature);

        if (!out.empty()) out += "\n";
        out += pair.feature;
        out += "=";
        out += hasFeature ? "1" : "0";
        out += ",";
        out += std::to_string(pair.sensorType);
        out += "=";
        out += hasSensor ? "1" : "0";
    }

    env->DeleteLocalRef(sensorManagerClass);
    env->DeleteLocalRef(packageManager);
    return out;
}

static std::string GetAndroidIdHash(JNIEnv* env, jobject context)
{
    jobject resolver = CallObject(env, context, "getContentResolver", "()Landroid/content/ContentResolver;");
    if (resolver == nullptr) return std::string();

    jclass secureClass = FindClass(env, "android/provider/Settings$Secure");
    if (secureClass == nullptr)
    {
        env->DeleteLocalRef(resolver);
        return std::string();
    }

    jmethodID getString = env->GetStaticMethodID(secureClass, "getString", "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
    if (ClearException(env) || getString == nullptr)
    {
        env->DeleteLocalRef(secureClass);
        env->DeleteLocalRef(resolver);
        return std::string();
    }

    jstring name = env->NewStringUTF("android_id");
    jstring value = static_cast<jstring>(env->CallStaticObjectMethod(secureClass, getString, resolver, name));
    ClearException(env);
    std::string raw = JStringToString(env, value);
    std::vector<uint8_t> bytes(raw.begin(), raw.end());
    std::string out = raw.empty() ? "" : std::to_string(AttestationKeys::Hash64(bytes));
    if (value != nullptr) env->DeleteLocalRef(value);
    if (name != nullptr) env->DeleteLocalRef(name);
    env->DeleteLocalRef(secureClass);
    env->DeleteLocalRef(resolver);
    return out;
}

static std::string GetJavaProperties(JNIEnv* env)
{
    jclass systemClass = FindClass(env, "java/lang/System");
    if (systemClass == nullptr) return std::string();

    jmethodID getProperty = env->GetStaticMethodID(systemClass, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;");
    if (ClearException(env) || getProperty == nullptr)
    {
        env->DeleteLocalRef(systemClass);
        return std::string();
    }

    const char* keys[] = {"os.version", "java.library.path", "java.io.tmpdir", "os.arch", "http.agent"};
    std::string out;
    for (const char* key : keys)
    {
        jstring name = env->NewStringUTF(key);
        jstring value = static_cast<jstring>(env->CallStaticObjectMethod(systemClass, getProperty, name));
        ClearException(env);
        if (!out.empty()) out += "\n";
        out += key;
        out += "=";
        out += JStringToString(env, value);
        if (value != nullptr) env->DeleteLocalRef(value);
        if (name != nullptr) env->DeleteLocalRef(name);
    }

    env->DeleteLocalRef(systemClass);
    return out;
}

static void AddStringArray(Protocol::Builder& protocol, uint64_t fieldId, const std::vector<std::string>& values)
{
    Protocol::Builder nested = Protocol::Create();
    for (size_t index = 0; index < values.size(); ++index)
    {
        nested.AddString(SignalIds::ARRAY_ITEM_BASE + static_cast<uint64_t>(index), values[index]);
    }
    protocol.AddNested(fieldId, nested);
}

void FrameworkSignals::AddFrameworkSignals(JNIEnv* env, jobject context, Protocol::Builder& protocol)
{
    protocol.AddString(SignalIds::BUILD_FINGERPRINT, GetStaticStringField(env, "android/os/Build", "FINGERPRINT"));
    protocol.AddString(SignalIds::BUILD_BRAND, GetStaticStringField(env, "android/os/Build", "BRAND"));
    protocol.AddString(SignalIds::BUILD_PRODUCT, GetStaticStringField(env, "android/os/Build", "PRODUCT"));
    protocol.AddString(SignalIds::BUILD_DEVICE, GetStaticStringField(env, "android/os/Build", "DEVICE"));
    protocol.AddString(SignalIds::BUILD_ID, GetStaticStringField(env, "android/os/Build", "ID"));
    protocol.AddString(SignalIds::BUILD_TYPE, GetStaticStringField(env, "android/os/Build", "TYPE"));
    protocol.AddString(SignalIds::BUILD_TAGS, GetStaticStringField(env, "android/os/Build", "TAGS"));
    protocol.AddString(SignalIds::BUILD_MODEL, GetStaticStringField(env, "android/os/Build", "MODEL"));
    protocol.AddString(SignalIds::BUILD_MANUFACTURER, GetStaticStringField(env, "android/os/Build", "MANUFACTURER"));
    protocol.AddString(SignalIds::BUILD_BOARD, GetStaticStringField(env, "android/os/Build", "BOARD"));
    protocol.AddString(SignalIds::BUILD_RELEASE, GetStaticStringField(env, "android/os/Build$VERSION", "RELEASE"));
    protocol.AddString(SignalIds::BUILD_INCREMENTAL, GetStaticStringField(env, "android/os/Build$VERSION", "INCREMENTAL"));
    protocol.AddUInt64(SignalIds::BUILD_SDK, static_cast<uint64_t>(GetStaticIntField(env, "android/os/Build$VERSION", "SDK_INT")));
    AddStringArray(protocol, SignalIds::BUILD_SUPPORTED_ABIS, GetStaticStringArray(env, "android/os/Build", "SUPPORTED_ABIS"));

    std::string packageName = GetPackageName(env, context);
    std::string sourceDir = GetApplicationInfoStringField(env, context, "sourceDir");
    protocol.AddString(SignalIds::APP_PACKAGE, packageName);
    protocol.AddString(SignalIds::APP_VERSION, GetAppVersion(env, context, packageName));
    protocol.AddString(SignalIds::APP_SOURCE_DIR, sourceDir);
    protocol.AddString(SignalIds::APP_DATA_DIR, GetApplicationInfoStringField(env, context, "dataDir"));
    jobject filesDir = CallObject(env, context, "getFilesDir", "()Ljava/io/File;");
    protocol.AddString(SignalIds::APP_FILES_DIR, GetFilePath(env, filesDir));
    if (filesDir != nullptr) env->DeleteLocalRef(filesDir);
    protocol.AddString(SignalIds::APP_INSTALLER, GetInstallerPackageName(env, context, packageName));
    protocol.AddUInt64(SignalIds::APP_SIGNERS_DIGEST64, GetAppSignersDigest64(env, context, packageName));

    protocol.AddString(SignalIds::DISPLAY_METRICS, GetDisplayMetrics(env, context));
    protocol.AddString(SignalIds::LOCALE_CURRENT, GetLocale(env));
    protocol.AddString(SignalIds::TIMEZONE_CURRENT, GetTimezone(env));

    protocol.AddString(SignalIds::GPU_GL_VENDOR, GetGlString(GL_VENDOR));
    protocol.AddString(SignalIds::GPU_GL_RENDERER, GetGlString(GL_RENDERER));
    protocol.AddString(SignalIds::GPU_GL_VERSION, GetGlString(GL_VERSION));

    ASensorManager* nativeSensorManager = GetNativeSensorManager();
    jobject sensorManager = GetSensorManager(env, context);
    std::string sensorInventory = GetNativeSensorInventory(nativeSensorManager);
    std::vector<uint8_t> sensorBytes(sensorInventory.begin(), sensorInventory.end());
    std::vector<uint8_t> activeSensorBytes = CallStaticByteArray(env, "com/reveny/devicecheck/SensorBridge", "collect", context);
    std::vector<uint8_t> fullSensorReport = sensorBytes;
    if (!activeSensorBytes.empty())
    {
        if (!fullSensorReport.empty()) fullSensorReport.push_back('\n');
        fullSensorReport.insert(fullSensorReport.end(), activeSensorBytes.begin(), activeSensorBytes.end());
    }
    protocol.AddUInt64(SignalIds::SENSORS_COUNT, static_cast<uint64_t>(GetNativeSensorCount(nativeSensorManager)));
    protocol.AddUInt64(SignalIds::SENSORS_INVENTORY_HASH64, AttestationKeys::Hash64(sensorBytes));
    protocol.AddString(SignalIds::SENSORS_FEATURE_PAIRS, GetFeatureSensorPairs(env, context, sensorManager));
    protocol.AddBytes(SignalIds::SENSORS_FULL_REPORT, fullSensorReport);
    protocol.AddUInt64(SignalIds::SENSORS_FULL_REPORT_HASH64, AttestationKeys::Hash64(fullSensorReport));
    protocol.AddUInt64(SignalIds::SENSORS_FULL_REPORT_SIZE, static_cast<uint64_t>(fullSensorReport.size()));
    if (sensorManager != nullptr) env->DeleteLocalRef(sensorManager);

    protocol.AddString(SignalIds::ID_ANDROID_ID_HASH64, GetAndroidIdHash(env, context));
    protocol.AddUInt64(SignalIds::ID_GSF_PRESENT, IsPackagePresent(env, context, "com.google.android.gsf"));

    std::string javaProperties = GetJavaProperties(env);
    std::vector<uint8_t> javaBytes(javaProperties.begin(), javaProperties.end());
    protocol.AddUInt64(SignalIds::JAVA_PROPERTIES_HASH64, AttestationKeys::Hash64(javaBytes));
    protocol.AddUInt64(SignalIds::JAVA_PROPERTIES_SIZE, static_cast<uint64_t>(javaBytes.size()));
}
