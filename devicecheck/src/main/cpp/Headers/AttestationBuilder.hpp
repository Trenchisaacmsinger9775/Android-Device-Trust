#pragma once

#include <cstdint>
#include <jni.h>
#include <vector>

namespace AttestationBuilder
{
    std::vector<uint8_t> Build(JNIEnv* env, jobject context, const std::vector<uint8_t>& challenge);
}
