#pragma once

#include "Protocol.hpp"

#include <jni.h>
#include <vector>

namespace KeystoreAttestation
{
    void AddKeystoreAttestation(JNIEnv* env, jobject context, const std::vector<uint8_t>& challenge, Protocol::Builder& protocol);
}
