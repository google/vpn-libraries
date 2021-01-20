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

import com.google.android.libraries.privacy.ppn.PpnTelemetry;
import com.google.auto.value.AutoValue;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@AutoValue
abstract class PpnTelemetryImpl implements PpnTelemetry {
  @Override
  public abstract Duration networkUptime();

  @Override
  public abstract Duration ppnConnectionUptime();

  @Override
  public abstract Duration ppnServiceUptime();

  @Override
  @SuppressWarnings("AutoValueImmutableFields")
  public abstract List<Duration> authLatency();

  @Override
  @SuppressWarnings("AutoValueImmutableFields")
  public abstract List<Duration> oauthLatency();

  @Override
  @SuppressWarnings("AutoValueImmutableFields")
  public abstract List<Duration> zincLatency();

  @Override
  @SuppressWarnings("AutoValueImmutableFields")
  public abstract List<Duration> egressLatency();

  @Override
  public abstract int successfulRekeys();

  @Override
  public abstract int networkSwitches();

  public static Builder builder() {
    // Assign default values for optional fields here.
    return new AutoValue_PpnTelemetryImpl.Builder()
        .setAuthLatency(new ArrayList<>())
        .setOauthLatency(new ArrayList<>())
        .setZincLatency(new ArrayList<>())
        .setEgressLatency(new ArrayList<>())
        .setNetworkSwitches(0)
        .setSuccessfulRekeys(0);
  }

  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setNetworkUptime(Duration value);

    public abstract Builder setPpnConnectionUptime(Duration value);

    public abstract Builder setPpnServiceUptime(Duration value);

    public abstract Builder setAuthLatency(List<Duration> value);

    public abstract Builder setOauthLatency(List<Duration> value);

    public abstract Builder setZincLatency(List<Duration> value);

    public abstract Builder setEgressLatency(List<Duration> value);

    public abstract Builder setSuccessfulRekeys(int value);

    public abstract Builder setNetworkSwitches(int value);

    public abstract PpnTelemetryImpl build();
  }
}
