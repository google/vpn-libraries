// Copyright 2022 Google LLC
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

package com.google.android.libraries.privacy.ppn.neon;

import com.google.android.libraries.privacy.ppn.proto.PpnIkeResponse;

/** Response from Ike#provision. */
public class ProvisionResponse {
  private final String serverAddress;
  private final byte[] clientId;
  private final byte[] sharedSecret;

  /** Constructs a new provision response. */
  public ProvisionResponse(String serverAddress, byte[] clientId, byte[] sharedSecret) {
    this.serverAddress = serverAddress;
    this.clientId = clientId;
    this.sharedSecret = sharedSecret;
  }

  /** Creates a ProvisionResponse from the corresponding proto. */
  @SuppressWarnings("CheckedExceptionNotThrown")
  public static ProvisionResponse createFromIkeResponse(PpnIkeResponse response)
      throws ProvisionException {
    String serverAddress = response.getServerAddress();
    byte[] clientId = response.getClientId().toByteArray();
    byte[] sharedSecret = response.getSharedSecret().toByteArray();
    return new ProvisionResponse(serverAddress, clientId, sharedSecret);
  }

  /** Returns the server address, which is used to set serverHostname in IkeSessionParams. */
  public String getServerAddress() {
    return serverAddress;
  }

  /** Returns the client ID for the IkeKeyIdIdentification for the localIdentification field. */
  public byte[] getClientId() {
    return clientId;
  }

  /** Returns the shared secret, which is used to set the authPsk field in IkeSessionParams. */
  public byte[] getSharedSecret() {
    return sharedSecret;
  }
}
