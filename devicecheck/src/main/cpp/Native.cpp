#include "AttestationBuilder.hpp"

#include <fcntl.h>
#include <jni.h>
#include <atomic>
#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <unistd.h>
#include <vector>

namespace
{
    static constexpr const char* expectedCmdline = "com.reveny.devicecheck";
    static constexpr const char* appKey = "72156d1c37c8e9fd52fdaf7d9ffcc9420a3f38a5095b8052abe104dfec066366";

    static std::string ReadCmdline()
    {
        int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return {};

        char buffer[256] = {};
        ssize_t bytesRead = read(fd, buffer, sizeof(buffer) - 1);
        close(fd);
        if (bytesRead <= 0) return {};

        size_t length = 0;
        while (length < static_cast<size_t>(bytesRead) && buffer[length] != '\0')
        {
            ++length;
        }
        return std::string(buffer, length);
    }

    static bool IsExpectedProcess()
    {
        return ReadCmdline() == expectedCmdline;
    }

    struct Welford
    {
        int samples = 0;
        double mean[3] = {};
        double m2[3] = {};

        void Add(const float* values, int offset)
        {
            ++samples;
            for (int index = 0; index < 3; ++index)
            {
                double value = static_cast<double>(values[offset + index]);
                double delta = value - mean[index];
                mean[index] += delta / static_cast<double>(samples);
                double delta2 = value - mean[index];
                m2[index] += delta * delta2;
            }
        }

        double Variance(int index) const
        {
            if (samples < 2) return 0.0;
            return m2[index] / static_cast<double>(samples - 1);
        }
    };

    struct RawSample
    {
        int64_t timestamp = 0;
        float values[8] = {};
        int count = 0;
    };

    struct SensorCapture
    {
        Welford accel;
        Welford gyroBias;
        Welford magneticBias;
        std::unordered_set<std::string> accelDistinct;
        std::vector<RawSample> accelSamples;
        std::vector<RawSample> gyroSamples;
        std::vector<RawSample> magneticSamples;
        std::vector<RawSample> rotationSamples;
        std::vector<RawSample> gameRotationSamples;
    };

    std::mutex gSensorCapturesLock;
    std::unordered_map<int64_t, SensorCapture> gSensorCaptures;
    std::atomic<int64_t> gNextSensorCapture{1};

    static std::string FloatValue(float value)
    {
        char buffer[64];
        std::snprintf(buffer, sizeof(buffer), "%.9g", value);
        return buffer;
    }

    static void AppendStats(std::string& out, const Welford& stats)
    {
        out += FloatValue(static_cast<float>(stats.mean[0]));
        out += ",";
        out += FloatValue(static_cast<float>(stats.mean[1]));
        out += ",";
        out += FloatValue(static_cast<float>(stats.mean[2]));
        out += "|";
        out += FloatValue(static_cast<float>(stats.Variance(0)));
        out += ",";
        out += FloatValue(static_cast<float>(stats.Variance(1)));
        out += ",";
        out += FloatValue(static_cast<float>(stats.Variance(2)));
    }

    static void AppendBias(std::string& out, const char* name, const Welford& stats)
    {
        out += name;
        out += "|";
        out += std::to_string(stats.samples);
        out += "|";
        AppendStats(out, stats);
        out += "\n";
    }

    static void AppendRawSamples(std::string& out, const char* name, const std::vector<RawSample>& samples)
    {
        for (const RawSample& sample : samples)
        {
            out += name;
            out += "|";
            out += std::to_string(sample.timestamp);
            out += "|";
            for (int index = 0; index < sample.count; ++index)
            {
                if (index > 0) out += ",";
                out += FloatValue(sample.values[index]);
            }
            out += "\n";
        }
    }

    static void AddRawSample(std::vector<RawSample>& samples, int64_t timestamp, const float* values, int count)
    {
        if (samples.size() >= 3) return;
        RawSample sample;
        sample.timestamp = timestamp;
        sample.count = count > 8 ? 8 : count;
        for (int index = 0; index < sample.count; ++index)
        {
            sample.values[index] = values[index];
        }
        samples.push_back(sample);
    }

    static std::string BuildSensorReport(const SensorCapture& capture)
    {
        std::string out;
        out += "accel_stats|";
        out += std::to_string(capture.accel.samples);
        out += "|";
        out += std::to_string(capture.accelDistinct.size());
        out += "|";
        AppendStats(out, capture.accel);
        out += "\n";
        AppendBias(out, "gyro_uncal_bias", capture.gyroBias);
        AppendBias(out, "magnetic_uncal_bias", capture.magneticBias);
        AppendRawSamples(out, "accel_sample", capture.accelSamples);
        AppendRawSamples(out, "gyro_uncal_sample", capture.gyroSamples);
        AppendRawSamples(out, "magnetic_uncal_sample", capture.magneticSamples);
        AppendRawSamples(out, "rotation_sample", capture.rotationSamples);
        AppendRawSamples(out, "game_rotation_sample", capture.gameRotationSamples);
        return out;
    }

    static jbyteArray NewByteArray(JNIEnv* env, const std::vector<uint8_t>& bytes)
    {
        jbyteArray result = env->NewByteArray(static_cast<jsize>(bytes.size()));
        if (result == nullptr) return nullptr;
        if (!bytes.empty())
        {
            env->SetByteArrayRegion(result, 0, static_cast<jsize>(bytes.size()), reinterpret_cast<const jbyte*>(bytes.data()));
        }
        return result;
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_reveny_devicecheck_Native_getBytes(JNIEnv* env, jclass, jobject context, jbyteArray challenge)
{
    if (!IsExpectedProcess()) return NewByteArray(env, {});

    std::vector<uint8_t> challengeBytes;
    if (challenge != nullptr)
    {
        jsize length = env->GetArrayLength(challenge);
        if (length > 0)
        {
            challengeBytes.resize(static_cast<size_t>(length));
            env->GetByteArrayRegion(challenge, 0, length, reinterpret_cast<jbyte*>(challengeBytes.data()));
            if (env->ExceptionCheck())
            {
                env->ExceptionClear();
                challengeBytes.clear();
            }
        }
    }

    std::vector<uint8_t> payload = AttestationBuilder::Build(env, context, challengeBytes);
    return NewByteArray(env, payload);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_reveny_devicecheck_Native_getAppKey(JNIEnv* env, jclass)
{
    if (!IsExpectedProcess()) return env->NewStringUTF("");
    return env->NewStringUTF(appKey);
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_reveny_devicecheck_Native_beginSensorCapture(JNIEnv*, jclass)
{
    int64_t handle = gNextSensorCapture.fetch_add(1);
    std::lock_guard<std::mutex> lock(gSensorCapturesLock);
    gSensorCaptures[handle] = SensorCapture();
    return static_cast<jlong>(handle);
}

extern "C" JNIEXPORT void JNICALL
Java_com_reveny_devicecheck_Native_pushSensorEvent(JNIEnv* env, jclass, jlong handle, jint type, jlong timestamp, jfloatArray values)
{
    if (handle == 0 || values == nullptr) return;

    jsize length = env->GetArrayLength(values);
    if (env->ExceptionCheck() || length <= 0)
    {
        env->ExceptionClear();
        return;
    }

    float buffer[8] = {};
    jsize copyLength = length > 8 ? 8 : length;
    env->GetFloatArrayRegion(values, 0, copyLength, buffer);
    if (env->ExceptionCheck())
    {
        env->ExceptionClear();
        return;
    }

    std::lock_guard<std::mutex> lock(gSensorCapturesLock);
    auto iterator = gSensorCaptures.find(static_cast<int64_t>(handle));
    if (iterator == gSensorCaptures.end()) return;

    SensorCapture& capture = iterator->second;
    if (type == 1 && copyLength >= 3)
    {
        if (capture.accel.samples < 3)
        {
            capture.accel.Add(buffer, 0);
            capture.accelDistinct.insert(FloatValue(buffer[0]) + "," + FloatValue(buffer[1]) + "," + FloatValue(buffer[2]));
        }
        AddRawSample(capture.accelSamples, static_cast<int64_t>(timestamp), buffer, 3);
    }
    else if (type == 16 && copyLength >= 6)
    {
        if (capture.gyroBias.samples < 3) capture.gyroBias.Add(buffer, 3);
        AddRawSample(capture.gyroSamples, static_cast<int64_t>(timestamp), buffer, 6);
    }
    else if (type == 14 && copyLength >= 6)
    {
        if (capture.magneticBias.samples < 3) capture.magneticBias.Add(buffer, 3);
        AddRawSample(capture.magneticSamples, static_cast<int64_t>(timestamp), buffer, 6);
    }
    else if (type == 11 && copyLength >= 3)
    {
        AddRawSample(capture.rotationSamples, static_cast<int64_t>(timestamp), buffer, copyLength);
    }
    else if (type == 15 && copyLength >= 3)
    {
        AddRawSample(capture.gameRotationSamples, static_cast<int64_t>(timestamp), buffer, copyLength);
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_reveny_devicecheck_Native_finishSensorCapture(JNIEnv* env, jclass, jlong handle)
{
    SensorCapture capture;
    {
        std::lock_guard<std::mutex> lock(gSensorCapturesLock);
        auto iterator = gSensorCaptures.find(static_cast<int64_t>(handle));
        if (iterator == gSensorCaptures.end()) return NewByteArray(env, {});
        capture = iterator->second;
        gSensorCaptures.erase(iterator);
    }

    std::string report = BuildSensorReport(capture);
    std::vector<uint8_t> bytes(report.begin(), report.end());
    return NewByteArray(env, bytes);
}
