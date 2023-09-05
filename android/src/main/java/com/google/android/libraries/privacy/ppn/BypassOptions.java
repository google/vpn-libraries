// Copyright 2023 Google LLC
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

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableSet;
import com.google.errorprone.annotations.Immutable;
import java.util.Set;

/** Options controlling bypassability of the VPN. */
@AutoValue
@Immutable
public abstract class BypassOptions {
  /**
   * Whether other apps are allowed to bypass the VPN and explicitly bind to a different network.
   */
  public abstract boolean allowBypass();

  /** Whether routes for local traffic will be excluded from the VPN. */
  public abstract boolean excludeLocalAddresses();

  /**
   * Package names of applications that will be denied access to the VPN. These applications will
   * use networking as if the VPN was not running.
   */
  public abstract ImmutableSet<String> disallowedApplications();

  public static Builder builder() {
    return new AutoValue_BypassOptions.Builder();
  }

  public abstract Builder toBuilder();

  /** Builder for {@link BypassOptions}. */
  @AutoValue.Builder
  public abstract static class Builder {
    /**
     * Whether other apps are allowed to bypass the VPN and explicitly bind to a different network.
     */
    public abstract Builder setAllowBypass(boolean allowBypass);

    /** Whether routes for local traffic will be excluded from the VPN. */
    public abstract Builder setExcludeLocalAddresses(boolean excludeLocalAddresses);

    /**
     * Package names of applications that will be denied access to the VPN. These applications will
     * use networking as if the VPN was not running.
     */
    public abstract Builder setDisallowedApplications(Set<String> disallowedApplications);

    public abstract BypassOptions build();
  }
}
