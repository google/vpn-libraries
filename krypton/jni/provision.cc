// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "privacy/net/krypton/provision.h"

#include <jni.h>
#include <jni_md.h>

#include <memory>
#include <string>

#include "base/logging.h"
#include "privacy/net/krypton/add_egress_response.h"
#include "privacy/net/krypton/egress_manager.h"
#include "privacy/net/krypton/jni/http_fetcher.h"
#include "privacy/net/krypton/jni/jni_cache.h"
#include "privacy/net/krypton/jni/jni_utils.h"
#include "privacy/net/krypton/jni/oauth.h"
#include "privacy/net/krypton/proto/krypton_config.proto.h"
#include "privacy/net/krypton/utils/looper.h"
#include "third_party/absl/status/status.h"
#include "third_party/absl/strings/string_view.h"

// Implementations of native methods from
// com.google.android.libraries.privacy.ppn.neon.Provision.
// LINT.IfChange
extern "C" {

JNIEXPORT jlong JNICALL
Java_com_google_android_libraries_privacy_ppn_neon_Provision_startNative(
    JNIEnv* env, jobject provision_instance, jbyteArray config_byte,
    jobject http_fetcher_instance, jobject oauth_token_provider_instance);

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_neon_Provision_stopNative(
    JNIEnv* env, jobject provision_instance, jlong context_pointer);
}

// LINT.ThenChange(//depot/google3/java/com/google/android/libraries/privacy/ppn/neon/Provision.java)

namespace privacy {
namespace krypton {
namespace jni {

/**
 * ProvisionContext owns any state that needs to be kept alive for the duration
 * of provisioning.
 */
class ProvisionContext : public Provision::NotificationInterface {
 public:
  ProvisionContext(JNIEnv* env, jobject provision_instance,
                   jbyteArray config_byte_array, jobject http_fetcher_instance,
                   jobject oauth_token_provider_instance) {
    auto jni_ppn = privacy::krypton::jni::JniCache::Get();
    jni_ppn->Init(env, true);

    std::string config_bytes =
        ConvertJavaByteArrayToString(env, config_byte_array);

    if (!config_.ParseFromString(config_bytes)) {
      LOG(ERROR) << "ProvisionContext::Start() called with invalid bytes.";
      return;
    }

    http_fetcher_ = std::make_unique<HttpFetcher>(http_fetcher_instance);
    oauth_ = std::make_unique<OAuth>(oauth_token_provider_instance);

    looper_ = std::make_unique<utils::LooperThread>("Provision Context");
    auth_ = std::make_unique<Auth>(config_, http_fetcher_.get(), oauth_.get(),
                                   looper_.get());
    egress_manager_ = std::make_unique<EgressManager>(
        config_, http_fetcher_.get(), looper_.get());
    provision_ =
        std::make_unique<Provision>(config_, auth_.get(), egress_manager_.get(),
                                    http_fetcher_.get(), looper_.get());

    provision_instance_ = std::make_unique<JavaObject>(provision_instance);

    provision_->RegisterNotificationHandler(this);
  }

  void Start() { provision_->Start(); }

  /** This must not be called from this class's LooperThread. */
  void Stop() {
    egress_manager_->Stop();
    auth_->Stop();
    looper_ = nullptr;
  }

  void Provisioned(const AddEgressResponse& response,
                   bool /*is_rekey*/) override {
    LOG(INFO) << "Provisioning succeeded. Passing response to Java.";

    auto ike = response.ike_response();
    if (!ike.ok()) {
      ProvisioningFailure(absl::InternalError("missing ike response"), false);
      return;
    }

    std::string ike_bytes;
    ike->SerializeToString(&ike_bytes);

    auto jni_ppn = privacy::krypton::jni::JniCache::Get();
    auto jni_env = jni_ppn->GetJavaEnv();
    if (!jni_env) {
      LOG(ERROR) << "Unable to get JavaEnv to call onProvisioned.";
      return;
    }

    (*jni_env)->CallVoidMethod(provision_instance_->get(),
                               jni_ppn->GetProvisionOnProvisionedMethod(),
                               reinterpret_cast<jlong>(this),
                               JavaByteArray(*jni_env, ike_bytes).get());
  }

  void ProvisioningFailure(absl::Status status, bool permanent) override {
    if (permanent) {
      LOG(ERROR) << "Unable to provision: " << status;
    } else {
      LOG(ERROR) << "Permanently unable to provision: " << status;
    }

    ppn::PpnStatusDetails details = utils::GetPpnStatusDetails(status);
    std::string details_bytes;
    details.SerializeToString(&details_bytes);

    auto jni_ppn = privacy::krypton::jni::JniCache::Get();
    auto jni_env = jni_ppn->GetJavaEnv();
    if (!jni_env) {
      LOG(ERROR) << "Unable to get JavaEnv to call onProvisioned.";
      return;
    }

    (*jni_env)->CallVoidMethod(
        provision_instance_->get(),
        jni_ppn->GetProvisionOnProvisioningFailureMethod(),
        reinterpret_cast<jlong>(this), status.raw_code(),
        JavaString(*jni_env, std::string(status.message())).get(),
        JavaByteArray(*jni_env, details_bytes).get(),
        static_cast<int>(permanent));
  }

 private:
  KryptonConfig config_;
  std::unique_ptr<HttpFetcher> http_fetcher_;
  std::unique_ptr<OAuth> oauth_;
  std::unique_ptr<utils::LooperThread> looper_;
  std::unique_ptr<Auth> auth_;
  std::unique_ptr<EgressManager> egress_manager_;
  std::unique_ptr<Provision> provision_;

  std::unique_ptr<JavaObject> provision_instance_;
};

}  // namespace jni
}  // namespace krypton
}  // namespace privacy

JNIEXPORT jlong JNICALL
Java_com_google_android_libraries_privacy_ppn_neon_Provision_startNative(
    JNIEnv* env, jobject provision_instance, jbyteArray config_byte_array,
    jobject http_fetcher_instance, jobject oauth_token_provider_instance) {
  LOG(INFO) << "Called Provision.start()";
  // The ProvisionContext object has to be owned by the Java layer, so we have
  // no choice but to allocate it on the heap and pass back a pointer.
  auto* context = new privacy::krypton::jni::ProvisionContext(
      env, provision_instance, config_byte_array, http_fetcher_instance,
      oauth_token_provider_instance);

  context->Start();

  // Return a pointer to the C++ object, so that Java can call into it again.
  return reinterpret_cast<jlong>(context);
}

JNIEXPORT void JNICALL
Java_com_google_android_libraries_privacy_ppn_neon_Provision_stopNative(
    JNIEnv* /*env*/, jobject /*provision_instance*/, jlong context_pointer) {
  auto* context = reinterpret_cast<privacy::krypton::jni::ProvisionContext*>(
      context_pointer);
  context->Stop();
  delete context;
}
