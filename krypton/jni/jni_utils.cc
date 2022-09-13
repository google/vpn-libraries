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

#include "privacy/net/krypton/jni/jni_utils.h"

#include <jni.h>

#include <string>

#include "base/logging.h"

namespace privacy {
namespace krypton {
namespace jni {

std::string ConvertJavaStringToUTF8(JNIEnv* env, jstring java_string) {
  // Convert Java string to std::string
  const jsize strLen = env->GetStringUTFLength(ABSL_DIE_IF_NULL(java_string));
  const char* char_buffer = env->GetStringUTFChars(java_string, nullptr);
  std::string str(char_buffer, strLen);

  // Release memory
  env->ReleaseStringUTFChars(java_string, char_buffer);
  env->DeleteLocalRef(java_string);
  return str;
}

std::string ConvertJavaByteArrayToString(JNIEnv* env, jbyteArray byte_array) {
  // Convert Java byte[] to std::string
  jbyte* bytes = env->GetByteArrayElements(byte_array, nullptr);
  jsize bytes_size = env->GetArrayLength(byte_array);
  std::string byte_string(reinterpret_cast<const char*>(bytes), bytes_size);

  // Release memory
  env->ReleaseByteArrayElements(byte_array, bytes, 0);
  env->DeleteLocalRef(byte_array);
  return byte_string;
}

}  // namespace jni
}  // namespace krypton
}  // namespace privacy
