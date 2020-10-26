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

package com.google.android.libraries.privacy.ppn.internal.service;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import android.net.VpnService;
import com.google.testing.mockito.Mocks;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

/** Unit test for {@link RouteManager}. */
@RunWith(RobolectricTestRunner.class)
@Config()
public class RouteManagerTest {
  @Rule public Mocks mocks = new Mocks(this);

  @Mock private VpnService.Builder mockBuilder;

  @Test
  public void addRoutes_addsRoutes() {
    RouteManager.addRoutes(mockBuilder);

    verify(mockBuilder, atLeastOnce()).addRoute(anyString(), anyInt());
    verifyNoMoreInteractions(mockBuilder);
  }
}
