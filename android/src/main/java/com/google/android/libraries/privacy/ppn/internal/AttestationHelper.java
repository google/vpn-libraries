/*
 * Copyright (C) 2021 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.android.libraries.privacy.ppn.internal;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.concurrent.TimeUnit.SECONDS;

import android.content.Context;
import android.net.Network;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.google.android.libraries.privacy.ppn.PpnOptions;
import com.google.android.libraries.privacy.ppn.proto.AndroidAttestationData;
import com.google.android.libraries.privacy.ppn.proto.AttestationData;
import com.google.android.play.core.integrity.IntegrityManager;
import com.google.android.play.core.integrity.IntegrityManagerFactory;
import com.google.android.play.core.integrity.IntegrityTokenRequest;
import com.google.android.play.core.integrity.IntegrityTokenResponse;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

/** Provides getAttestationData for OAuthTokenProvider. */
@RequiresApi(23)
public class AttestationHelper {
  private static final String TAG = "AttestationHelper";
  private static final String ANDROID_KEYSTORE_NAME = "AndroidKeyStore";
  private static final String HARDWARE_CERTIFICATE_ALIAS = "AndroidHardwareCerts";
  private static final String NONCE_HASH_FUNCTION = "SHA-256";
  private static final Duration INTEGRITY_TIMEOUT = Duration.ofSeconds(30);

  public static final String ANDROID_ATTESTATION_DATA_TYPE_URL =
      "type.googleapis.com/privacy.ppn.AndroidAttestationData";

  /** AttestationException is an exception for any attestation failure. */
  private static class AttestationException extends Exception {
    public AttestationException(String message, Throwable throwable) {
      super(message, throwable);
    }
  }

  private final PpnOptions options;
  private final IntegrityManager integrityManager;

  public AttestationHelper(Context context, PpnOptions options) {
    this.integrityManager = IntegrityManagerFactory.create(context.getApplicationContext());
    this.options = options;
  }

  /**
   * Returns attestation data.
   *
   * @return AndroidAttestationData as bytes or null on failure.
   */
  @Nullable
  public byte[] getAttestationData(String nonce, @Nullable Network network) {
    Log.w(TAG, "Getting attestation data with network: " + network);
    AndroidAttestationData.Builder data = AndroidAttestationData.newBuilder();
    String integrityToken;
    try {
      integrityToken = getIntegrityToken(nonce, network);
    } catch (AttestationException e) {
      Log.e(TAG, "Unable to fetch integrity token.", e);
      return null;
    }
    data = data.setAttestationToken(integrityToken);
    if (options.isHardwareAttestationEnabled()) {
      if (Build.VERSION.SDK_INT < 23) {
        Log.e(TAG, "Cannot perform hardware attestation on devices API 22 or lower.");
        return null;
      }
      try {
        data.addAllHardwareBackedCerts(getHardwareBackedCerts(nonce));
      } catch (AttestationException e) {
        // If we can't fetch them, then just leave them out. This happens on test devices that don't
        // have certificates. But we want the attestation to fail on the backend, not the client.
        Log.e(TAG, "Unable to get hardware-backed certs.", e);
      }
    }

    AttestationData attestationData =
        AttestationData.newBuilder()
            .setAttestationData(
                Any.newBuilder()
                    .setTypeUrl(ANDROID_ATTESTATION_DATA_TYPE_URL)
                    .setValue(data.build().toByteString()))
            .build();
    return attestationData.toByteArray();
  }

  private String getIntegrityToken(String nonce, @Nullable Network network)
      throws AttestationException {
    // Requests the integrity token by providing a nonce.
    try {
      IntegrityTokenRequest.Builder tokenRequestBuilder =
          IntegrityTokenRequest.builder().setNonce(nonce);
      if (!options.getAttestationCloudProjectNumber().isEmpty()) {
        tokenRequestBuilder.setCloudProjectNumber(options.getAttestationCloudProjectNumber().get());
      }
      if (network != null && options.isAttestationNetworkOverrideEnabled()) {
        tokenRequestBuilder.setNetwork(network);
      }
      Task<IntegrityTokenResponse> task =
          integrityManager.requestIntegrityToken(tokenRequestBuilder.build());
      IntegrityTokenResponse token = Tasks.await(task, INTEGRITY_TIMEOUT.getSeconds(), SECONDS);
      return token.token();
    } catch (ExecutionException | InterruptedException | TimeoutException e) {
      throw new AttestationException("Failed to retrieve integrity token", e);
    }
  }

  private List<ByteString> getHardwareBackedCerts(String nonce) throws AttestationException {
    KeyPairGenerator keyPairGenerator;
    try {
      keyPairGenerator =
          KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE_NAME);
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new AttestationException("Failed to fetch RSA KeyPairGenerator", e);
    }

    try {
      keyPairGenerator.initialize(buildKeyGenParameterSpec(nonce));
    } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
      throw new AttestationException("Failed to generate hardware certificates", e);
    }
    // Result of Key pair generation is unused but is necessary to generate the certificates (?)
    // according to the Android documentation:
    // https://source.android.com/security/keystore/attestation#expandable-1
    try {
      keyPairGenerator.generateKeyPair();
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE_NAME);
      keyStore.load(null);
      Certificate[] certs = keyStore.getCertificateChain(HARDWARE_CERTIFICATE_ALIAS);
      List<ByteString> certList = new ArrayList<>();
      for (Certificate cert : certs) {
        certList.add(ByteString.copyFrom(cert.getEncoded()));
      }
      return certList;
    } catch (KeyStoreException
        | CertificateException
        | IOException
        | NoSuchAlgorithmException
        | ProviderException e) {
      throw new AttestationException("Failed to retrieve hardware certificates", e);
    }
  }

  private static KeyGenParameterSpec buildKeyGenParameterSpec(String nonce)
      throws NoSuchAlgorithmException {
    // KeyGenParameterSpec was added in 23+ and is required to properly generate the
    // hardware-attested IDs.
    return new KeyGenParameterSpec.Builder(HARDWARE_CERTIFICATE_ALIAS, KeyProperties.PURPOSE_SIGN)
        .setAlgorithmParameterSpec(
            new RSAKeyGenParameterSpec(
                /*keySize*/ 2048, /*bigExponent*/ RSAKeyGenParameterSpec.F4 /*==65537*/))
        .setDigests(KeyProperties.DIGEST_SHA256)
        // PPN should be able to re-attest while phone is not being used and PPN is on.
        .setUserAuthenticationRequired(false)
        .setDevicePropertiesAttestationIncluded(true)
        .setAttestationChallenge(sha256(nonce.getBytes(UTF_8)))
        .build();
  }

  private static byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance(NONCE_HASH_FUNCTION);
    return digest.digest(data);
  }
}
