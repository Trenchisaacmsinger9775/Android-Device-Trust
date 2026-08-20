#include "KeystoreAttestation.hpp"

#include "SignalIds.hpp"

#include <cstdint>
#include <string>

static constexpr const char* identityKeyAlias = "r7m2c9f4a0b6e1d8";
static constexpr const char* attestationKeyAlias = "p4a8f1c6d9e3b0a7";
static constexpr int purposeSignVerify = 12;

static bool ClearException(JNIEnv* env)
{
    if (!env->ExceptionCheck()) return false;
    env->ExceptionClear();
    return true;
}

static jclass FindClass(JNIEnv* env, const char* name)
{
    jclass clazz = env->FindClass(name);
    if (ClearException(env)) return nullptr;
    return clazz;
}

static jstring NewString(JNIEnv* env, const char* value)
{
    jstring string = env->NewStringUTF(value);
    if (ClearException(env)) return nullptr;
    return string;
}

static jbyteArray ToByteArray(JNIEnv* env, const std::vector<uint8_t>& bytes)
{
    jbyteArray array = env->NewByteArray(static_cast<jsize>(bytes.size()));
    if (!array || ClearException(env)) return nullptr;
    if (!bytes.empty())
    {
        env->SetByteArrayRegion(array, 0, static_cast<jsize>(bytes.size()), reinterpret_cast<const jbyte*>(bytes.data()));
        if (ClearException(env)) return nullptr;
    }
    return array;
}

static std::vector<uint8_t> FromByteArray(JNIEnv* env, jbyteArray array)
{
    if (!array) return {};
    jsize length = env->GetArrayLength(array);
    if (ClearException(env) || length <= 0) return {};
    std::vector<uint8_t> bytes(static_cast<size_t>(length));
    env->GetByteArrayRegion(array, 0, length, reinterpret_cast<jbyte*>(bytes.data()));
    if (ClearException(env)) return {};
    return bytes;
}

static jobject CallStaticObject(JNIEnv* env, jclass clazz, const char* name, const char* signature, jvalue* args)
{
    if (!clazz) return nullptr;
    jmethodID method = env->GetStaticMethodID(clazz, name, signature);
    if (!method || ClearException(env)) return nullptr;
    jobject object = env->CallStaticObjectMethodA(clazz, method, args);
    if (ClearException(env)) return nullptr;
    return object;
}

static jobject CallObject(JNIEnv* env, jobject object, const char* name, const char* signature, jvalue* args)
{
    if (!object) return nullptr;
    jclass clazz = env->GetObjectClass(object);
    if (!clazz || ClearException(env)) return nullptr;
    jmethodID method = env->GetMethodID(clazz, name, signature);
    env->DeleteLocalRef(clazz);
    if (!method || ClearException(env)) return nullptr;
    jobject result = env->CallObjectMethodA(object, method, args);
    if (ClearException(env)) return nullptr;
    return result;
}

static bool CallVoid(JNIEnv* env, jobject object, const char* name, const char* signature, jvalue* args)
{
    if (!object) return false;
    jclass clazz = env->GetObjectClass(object);
    if (!clazz || ClearException(env)) return false;
    jmethodID method = env->GetMethodID(clazz, name, signature);
    env->DeleteLocalRef(clazz);
    if (!method || ClearException(env)) return false;
    env->CallVoidMethodA(object, method, args);
    return !ClearException(env);
}

static bool CallBoolean(JNIEnv* env, jobject object, const char* name, const char* signature, jvalue* args)
{
    if (!object) return false;
    jclass clazz = env->GetObjectClass(object);
    if (!clazz || ClearException(env)) return false;
    jmethodID method = env->GetMethodID(clazz, name, signature);
    env->DeleteLocalRef(clazz);
    if (!method || ClearException(env)) return false;
    jboolean result = env->CallBooleanMethodA(object, method, args);
    if (ClearException(env)) return false;
    return result == JNI_TRUE;
}

static bool HasStrongBox(JNIEnv* env, jobject context)
{
    jvalue noArgs[1]{};
    jobject packageManager = CallObject(env, context, "getPackageManager", "()Landroid/content/pm/PackageManager;", noArgs);
    if (!packageManager) return false;
    jstring feature = NewString(env, "android.hardware.strongbox_keystore");
    if (!feature)
    {
        env->DeleteLocalRef(packageManager);
        return false;
    }
    jvalue args[1];
    args[0].l = feature;
    bool result = CallBoolean(env, packageManager, "hasSystemFeature", "(Ljava/lang/String;)Z", args);
    env->DeleteLocalRef(feature);
    env->DeleteLocalRef(packageManager);
    return result;
}

static jobject LoadKeyStore(JNIEnv* env)
{
    jclass keyStoreClass = FindClass(env, "java/security/KeyStore");
    jstring provider = NewString(env, "AndroidKeyStore");
    if (!keyStoreClass || !provider) return nullptr;

    jvalue getArgs[1];
    getArgs[0].l = provider;
    jobject keyStore = CallStaticObject(env, keyStoreClass, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyStore;", getArgs);
    env->DeleteLocalRef(provider);
    env->DeleteLocalRef(keyStoreClass);
    if (!keyStore) return nullptr;

    jvalue loadArgs[1];
    loadArgs[0].l = nullptr;
    if (!CallVoid(env, keyStore, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", loadArgs))
    {
        env->DeleteLocalRef(keyStore);
        return nullptr;
    }
    return keyStore;
}

static void DeleteAlias(JNIEnv* env, jobject keyStore, jstring alias)
{
    jvalue args[1];
    args[0].l = alias;
    CallVoid(env, keyStore, "deleteEntry", "(Ljava/lang/String;)V", args);
    ClearException(env);
}

static jobject NewKeySpec(JNIEnv* env, jstring alias, jbyteArray challenge, bool strongBoxBacked)
{
    jclass builderClass = FindClass(env, "android/security/keystore/KeyGenParameterSpec$Builder");
    if (!builderClass) return nullptr;

    jmethodID ctor = env->GetMethodID(builderClass, "<init>", "(Ljava/lang/String;I)V");
    if (!ctor || ClearException(env))
    {
        env->DeleteLocalRef(builderClass);
        return nullptr;
    }

    jobject builder = env->NewObject(builderClass, ctor, alias, purposeSignVerify);
    env->DeleteLocalRef(builderClass);
    if (!builder || ClearException(env)) return nullptr;

    jclass stringClass = FindClass(env, "java/lang/String");
    jstring digest = NewString(env, "SHA-256");
    if (!stringClass || !digest)
    {
        env->DeleteLocalRef(builder);
        return nullptr;
    }

    jobjectArray digests = env->NewObjectArray(1, stringClass, digest);
    env->DeleteLocalRef(stringClass);
    env->DeleteLocalRef(digest);
    if (!digests || ClearException(env))
    {
        env->DeleteLocalRef(builder);
        return nullptr;
    }

    jvalue digestArgs[1];
    digestArgs[0].l = digests;
    jobject next = CallObject(env, builder, "setDigests", "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;", digestArgs);
    env->DeleteLocalRef(digests);
    env->DeleteLocalRef(builder);
    if (!next) return nullptr;
    builder = next;

    jvalue authArgs[1];
    authArgs[0].z = JNI_FALSE;
    next = CallObject(env, builder, "setUserAuthenticationRequired", "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;", authArgs);
    env->DeleteLocalRef(builder);
    if (!next) return nullptr;
    builder = next;

    jvalue challengeArgs[1];
    challengeArgs[0].l = challenge;
    next = CallObject(env, builder, "setAttestationChallenge", "([B)Landroid/security/keystore/KeyGenParameterSpec$Builder;", challengeArgs);
    env->DeleteLocalRef(builder);
    if (!next) return nullptr;
    builder = next;

    if (strongBoxBacked)
    {
        jvalue strongBoxArgs[1];
        strongBoxArgs[0].z = JNI_TRUE;
        next = CallObject(env, builder, "setIsStrongBoxBacked", "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;", strongBoxArgs);
        env->DeleteLocalRef(builder);
        if (!next) return nullptr;
        builder = next;
    }

    jvalue buildArgs[1]{};
    jobject spec = CallObject(env, builder, "build", "()Landroid/security/keystore/KeyGenParameterSpec;", buildArgs);
    env->DeleteLocalRef(builder);
    return spec;
}

static bool GenerateKey(JNIEnv* env, const char* aliasName, const std::vector<uint8_t>& challenge, bool strongBoxBacked, bool deleteExisting)
{
    jobject keyStore = LoadKeyStore(env);
    jstring alias = NewString(env, aliasName);
    jbyteArray challengeArray = ToByteArray(env, challenge);
    if (!keyStore || !alias || !challengeArray) return false;

    if (deleteExisting) DeleteAlias(env, keyStore, alias);
    jobject spec = NewKeySpec(env, alias, challengeArray, strongBoxBacked);
    env->DeleteLocalRef(challengeArray);
    if (!spec)
    {
        env->DeleteLocalRef(alias);
        env->DeleteLocalRef(keyStore);
        return false;
    }

    jclass generatorClass = FindClass(env, "java/security/KeyPairGenerator");
    jstring algorithm = NewString(env, "EC");
    jstring provider = NewString(env, "AndroidKeyStore");
    if (!generatorClass || !algorithm || !provider)
    {
        env->DeleteLocalRef(spec);
        env->DeleteLocalRef(alias);
        env->DeleteLocalRef(keyStore);
        return false;
    }

    jvalue getArgs[2];
    getArgs[0].l = algorithm;
    getArgs[1].l = provider;
    jobject generator = CallStaticObject(env, generatorClass, "getInstance", "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;", getArgs);
    env->DeleteLocalRef(algorithm);
    env->DeleteLocalRef(provider);
    env->DeleteLocalRef(generatorClass);
    if (!generator)
    {
        env->DeleteLocalRef(spec);
        env->DeleteLocalRef(alias);
        env->DeleteLocalRef(keyStore);
        return false;
    }

    jvalue initArgs[1];
    initArgs[0].l = spec;
    bool initialized = CallVoid(env, generator, "initialize", "(Ljava/security/spec/AlgorithmParameterSpec;)V", initArgs);
    env->DeleteLocalRef(spec);
    if (!initialized)
    {
        env->DeleteLocalRef(generator);
        env->DeleteLocalRef(alias);
        env->DeleteLocalRef(keyStore);
        return false;
    }

    jvalue generateArgs[1]{};
    jobject keyPair = CallObject(env, generator, "generateKeyPair", "()Ljava/security/KeyPair;", generateArgs);
    if (keyPair) env->DeleteLocalRef(keyPair);
    env->DeleteLocalRef(generator);
    env->DeleteLocalRef(alias);
    env->DeleteLocalRef(keyStore);
    return keyPair != nullptr;
}

static std::vector<std::vector<uint8_t>> ReadCertificateChain(JNIEnv* env, const char* aliasName)
{
    std::vector<std::vector<uint8_t>> chain;
    jobject keyStore = LoadKeyStore(env);
    jstring alias = NewString(env, aliasName);
    if (!keyStore || !alias) return chain;

    jvalue args[1];
    args[0].l = alias;
    auto array = static_cast<jobjectArray>(CallObject(env, keyStore, "getCertificateChain", "(Ljava/lang/String;)[Ljava/security/cert/Certificate;", args));
    env->DeleteLocalRef(alias);
    env->DeleteLocalRef(keyStore);
    if (!array) return chain;

    jsize count = env->GetArrayLength(array);
    if (ClearException(env) || count <= 0)
    {
        env->DeleteLocalRef(array);
        return chain;
    }

    for (jsize index = 0; index < count; ++index)
    {
        jobject cert = env->GetObjectArrayElement(array, index);
        if (ClearException(env) || !cert) continue;
        jvalue noArgs[1]{};
        auto encoded = static_cast<jbyteArray>(CallObject(env, cert, "getEncoded", "()[B", noArgs));
        std::vector<uint8_t> bytes = FromByteArray(env, encoded);
        if (!bytes.empty()) chain.push_back(bytes);
        if (encoded) env->DeleteLocalRef(encoded);
        env->DeleteLocalRef(cert);
    }
    env->DeleteLocalRef(array);
    return chain;
}

static std::vector<uint8_t> SignChallenge(JNIEnv* env, const char* aliasName, const std::vector<uint8_t>& challenge)
{
    jobject keyStore = LoadKeyStore(env);
    jstring alias = NewString(env, aliasName);
    if (!keyStore || !alias) return {};

    jvalue keyArgs[2];
    keyArgs[0].l = alias;
    keyArgs[1].l = nullptr;
    jobject privateKey = CallObject(env, keyStore, "getKey", "(Ljava/lang/String;[C)Ljava/security/Key;", keyArgs);
    env->DeleteLocalRef(alias);
    env->DeleteLocalRef(keyStore);
    if (!privateKey) return {};

    jclass signatureClass = FindClass(env, "java/security/Signature");
    jstring algorithm = NewString(env, "SHA256withECDSA");
    if (!signatureClass || !algorithm)
    {
        env->DeleteLocalRef(privateKey);
        return {};
    }

    jvalue getArgs[1];
    getArgs[0].l = algorithm;
    jobject signature = CallStaticObject(env, signatureClass, "getInstance", "(Ljava/lang/String;)Ljava/security/Signature;", getArgs);
    env->DeleteLocalRef(algorithm);
    env->DeleteLocalRef(signatureClass);
    if (!signature)
    {
        env->DeleteLocalRef(privateKey);
        return {};
    }

    jvalue signArgs[1];
    signArgs[0].l = privateKey;
    bool ready = CallVoid(env, signature, "initSign", "(Ljava/security/PrivateKey;)V", signArgs);
    env->DeleteLocalRef(privateKey);
    if (!ready)
    {
        env->DeleteLocalRef(signature);
        return {};
    }

    jbyteArray challengeArray = ToByteArray(env, challenge);
    if (!challengeArray)
    {
        env->DeleteLocalRef(signature);
        return {};
    }

    jvalue updateArgs[1];
    updateArgs[0].l = challengeArray;
    bool updated = CallVoid(env, signature, "update", "([B)V", updateArgs);
    env->DeleteLocalRef(challengeArray);
    if (!updated)
    {
        env->DeleteLocalRef(signature);
        return {};
    }

    jvalue noArgs[1]{};
    auto signatureBytes = static_cast<jbyteArray>(CallObject(env, signature, "sign", "()[B", noArgs));
    std::vector<uint8_t> bytes = FromByteArray(env, signatureBytes);
    if (signatureBytes) env->DeleteLocalRef(signatureBytes);
    env->DeleteLocalRef(signature);
    return bytes;
}

static void AddChain(Protocol::Builder& protocol, uint64_t chainId, uint64_t countId, uint64_t itemBase, const std::vector<std::vector<uint8_t>>& chain)
{
    Protocol::Builder chainProtocol = Protocol::Create();
    chainProtocol.AddUInt64(countId, static_cast<uint64_t>(chain.size()));
    for (size_t index = 0; index < chain.size(); ++index)
    {
        chainProtocol.AddBytes(itemBase + static_cast<uint64_t>(index), chain[index]);
    }

    protocol.AddNested(chainId, chainProtocol);
}

static bool EnsureIdentityKey(JNIEnv* env, const std::vector<uint8_t>& challenge, bool strongBox, std::vector<std::vector<uint8_t>>& chain, std::vector<uint8_t>& signature)
{
    chain = ReadCertificateChain(env, identityKeyAlias);
    signature = SignChallenge(env, identityKeyAlias, challenge);
    if (!chain.empty() && !signature.empty()) return true;

    bool generated = GenerateKey(env, identityKeyAlias, challenge, strongBox, true);
    if (!generated && strongBox) generated = GenerateKey(env, identityKeyAlias, challenge, false, true);
    if (!generated) return false;

    chain = ReadCertificateChain(env, identityKeyAlias);
    signature = SignChallenge(env, identityKeyAlias, challenge);
    return !chain.empty() && !signature.empty();
}

static bool GenerateFreshAttestationKey(JNIEnv* env, const std::vector<uint8_t>& challenge, bool strongBox, std::vector<std::vector<uint8_t>>& chain, std::vector<uint8_t>& signature)
{
    bool generated = GenerateKey(env, attestationKeyAlias, challenge, strongBox, true);
    if (!generated && strongBox) generated = GenerateKey(env, attestationKeyAlias, challenge, false, true);
    if (!generated) return false;

    chain = ReadCertificateChain(env, attestationKeyAlias);
    signature = SignChallenge(env, attestationKeyAlias, challenge);
    return !chain.empty() && !signature.empty();
}

void KeystoreAttestation::AddKeystoreAttestation(JNIEnv* env, jobject context, const std::vector<uint8_t>& challenge, Protocol::Builder& protocol)
{
    bool strongBox = HasStrongBox(env, context);
    std::vector<std::vector<uint8_t>> identityChain;
    std::vector<uint8_t> identitySignature;
    bool identityReady = EnsureIdentityKey(env, challenge, strongBox, identityChain, identitySignature);

    std::vector<std::vector<uint8_t>> attestationChain;
    std::vector<uint8_t> attestationSignature;
    bool attestationReady = GenerateFreshAttestationKey(env, challenge, strongBox, attestationChain, attestationSignature);

    protocol.AddUInt64(SignalIds::KEY_ATTESTATION_STRONGBOX_REQUESTED, strongBox ? 1 : 0);
    protocol.AddUInt64(SignalIds::KEY_IDENTITY_STATUS, identityReady ? 0 : 1);
    if (identityReady)
    {
        AddChain(protocol, SignalIds::KEY_IDENTITY_CERT_CHAIN, SignalIds::KEY_IDENTITY_CERT_COUNT, SignalIds::KEY_IDENTITY_CERT_ITEM_BASE, identityChain);
        protocol.AddBytes(SignalIds::KEY_IDENTITY_SIGNATURE, identitySignature);
    }

    protocol.AddUInt64(SignalIds::KEY_ATTESTATION_STATUS, attestationReady ? 0 : 1);
    if (attestationReady)
    {
        AddChain(protocol, SignalIds::KEY_ATTESTATION_CERT_CHAIN, SignalIds::KEY_ATTESTATION_CERT_COUNT, SignalIds::KEY_ATTESTATION_CERT_ITEM_BASE, attestationChain);
        protocol.AddBytes(SignalIds::KEY_ATTESTATION_SIGNATURE, attestationSignature);
    }
}
