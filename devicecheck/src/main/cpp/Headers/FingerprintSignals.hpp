#pragma once

#include "Protocol.hpp"

#include <jni.h>

namespace FingerprintSignals
{
    void AddFingerprintSignals(JNIEnv* env, jobject context, Protocol::Builder& protocol);
}
