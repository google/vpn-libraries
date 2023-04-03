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

package com.google.android.libraries.privacy.ppn.internal.service;

import com.google.android.libraries.privacy.ppn.internal.json.Json;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import org.json.JSONObject;

/** Debug info about the PPN VPN Service. */
public class PpnServiceDebugJson {
  private PpnServiceDebugJson() {}

  public static final String RUNNING = "running";

  /** Convenience builder for creating making the json. */
  public static class Builder {
    private final JSONObject json = new JSONObject();

    @CanIgnoreReturnValue
    public Builder setRunning(boolean running) {
      Json.put(json, RUNNING, running);
      return this;
    }

    public JSONObject build() {
      return json;
    }
  }
}
