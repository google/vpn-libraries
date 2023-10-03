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

package com.google.android.libraries.privacy.ppn.krypton;

import com.google.android.libraries.privacy.ppn.internal.IpSecTransformParams;

/** Helper class for configuring IPSec sessions in Android Krypton library. */
public interface KryptonIpSecHelper {

  /** Constructs and applies an IPSecTransform. */
  void transformFd(
      IpSecTransformParams params, boolean socketKeepaliveEnabled, Runnable keepaliveStartCallback)
      throws KryptonException;

  /**
   * Removes the transforms that were applied to the file descriptor.
   *
   * @param networkFd a network file descriptor
   */
  void removeTransformFromFd(int networkFd) throws KryptonException;
}
