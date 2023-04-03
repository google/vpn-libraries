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

package com.google.android.libraries.privacy.ppn;

import android.content.Context;
import com.google.android.libraries.privacy.ppn.PpnOptions.DatapathProtocol;
import com.google.android.libraries.privacy.ppn.internal.PpnImpl;
import com.google.android.libraries.privacy.ppn.neon.IkePpnImpl;

/** PpnFactory creates instances of Ppn. */
public class PpnFactory {
  private PpnFactory() {}

  /** Returns a new instance of the Ppn library. */
  public static Ppn create(Context context, PpnOptions options) {
    if (options.getDatapathProtocol().isPresent()
        && options.getDatapathProtocol().get() == DatapathProtocol.IKE) {
      return new IkePpnImpl(context, options);
    }
    return new PpnImpl(context, options);
  }
}
