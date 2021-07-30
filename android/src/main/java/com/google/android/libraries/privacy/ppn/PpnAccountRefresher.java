// Copyright 2021 Google LLC
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

package com.google.android.libraries.privacy.ppn;

import android.content.Context;
import android.net.Network;
import androidx.annotation.Nullable;

/**
 * Common interface for starting a background refresher of a user account. This also acts as a cache
 * for the user's account information.
 */
public interface PpnAccountRefresher {

  /** Starts the AccountRefresher. */
  void start();

  /** Stops the AccountRefresher. */
  void stop();

  /** Returns a token for the AccountRefresher's user account. */
  String getToken(Context context, @Nullable Network network) throws PpnException;
}
