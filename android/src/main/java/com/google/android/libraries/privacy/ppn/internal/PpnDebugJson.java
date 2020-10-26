// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the );
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an  BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.android.libraries.privacy.ppn.internal;

import com.google.android.libraries.privacy.ppn.internal.json.Json;
import org.json.JSONObject;

/** Utility class for creating and using PPN debug json. */
public class PpnDebugJson {
  private PpnDebugJson() {}

  public static final String SERVICE = "service";
  public static final String KRYPTON = "krypton";
  public static final String XENON = "xenon";

  /** Builder for creating instances of PpnDebugJson. */
  public static class Builder {
    private final JSONObject json = new JSONObject();

    public Builder setServiceDebugJson(JSONObject service) {
      Json.put(json, SERVICE, service);
      return this;
    }

    public Builder setKryptonDebugJson(JSONObject krypton) {
      Json.put(json, KRYPTON, krypton);
      return this;
    }

    public Builder setXenonDebugJson(JSONObject xenon) {
      Json.put(json, XENON, xenon);
      return this;
    }

    public JSONObject build() {
      return json;
    }
  }
}
