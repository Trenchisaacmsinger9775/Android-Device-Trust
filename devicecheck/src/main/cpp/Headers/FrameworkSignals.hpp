#pragma once

#include "Protocol.hpp"

#include <jni.h>
#include <string>
#include <vector>

namespace FrameworkSignals
{
    void AddFrameworkSignals(JNIEnv* env, jobject context, Protocol::Builder& protocol);
}
