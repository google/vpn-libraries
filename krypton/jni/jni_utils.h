// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_NET_KRYPTON_JNI_JNI_UTILS_H_
#define PRIVACY_NET_KRYPTON_JNI_JNI_UTILS_H_

#include <jni.h>
#include <jni_md.h>

#include <string>

namespace privacy {
namespace krypton {
namespace jni {

// Converts a jstring to a std::string in UTF8 and releases the memory of the
// jstring.
std::string ConvertJavaStringToUTF8(JNIEnv* env, jstring java_string);

// Converts a jbyteArray to a std::string in UTF8 and releases the memory of the
// jbyteArray.
std::string ConvertJavaByteArrayToString(JNIEnv* env, jbyteArray byte_array);

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

#endif  // PRIVACY_NET_KRYPTON_JNI_JNI_UTILS_H_
