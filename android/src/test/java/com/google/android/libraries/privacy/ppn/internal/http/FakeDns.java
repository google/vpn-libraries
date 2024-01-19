// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "LICENSE");
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

package com.google.android.libraries.privacy.ppn.internal.http;

import com.google.common.collect.ImmutableList;
import java.net.InetAddress;
import java.util.List;

/**
 * A Fake implementation of the {@link Dns} interface. This implementation allows tests to perform
 * fake DNS queries and does not require network access.
 */
public final class FakeDns implements Dns {

  public FakeDns() {}

  /** Returns the loopback address for all DNS lookups. */
  @Override
  public List<InetAddress> lookup(String hostname) {
    return ImmutableList.of(InetAddress.getLoopbackAddress());
  }
}
