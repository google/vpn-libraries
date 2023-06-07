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

package com.google.android.libraries.privacy.ppn.krypton;

import com.google.android.libraries.privacy.ppn.internal.DatapathDebugInfo;
import com.google.android.libraries.privacy.ppn.internal.KryptonDebugInfo;
import com.google.android.libraries.privacy.ppn.internal.json.Json;
import org.json.JSONArray;
import org.json.JSONObject;

/** Debug info about the Krypton library. */
public class KryptonDebugJson {
  private KryptonDebugJson() {}

  public static final String ZINC_URL = "zincUrl";
  public static final String BRASS_URL = "brassUrl";
  public static final String SERVICE_TYPE = "serviceType";
  public static final String CANCELLED = "cancelled";

  // Reconnector
  public static final String RECONNECTOR_STATE = "reconnectorState";
  public static final String SESSION_RESTART_COUNTER = "sessionRestartCounter";
  public static final String SUCCESSIVE_CONTROL_PLANE_FAILURES = "successiveControlPlaneFailures";
  public static final String SUCCESSIVE_DATA_PLANE_FAILURES = "successiveDataPlaneFailures";

  // Auth
  public static final String AUTH_STATE = "authState";
  public static final String AUTH_STATUS = "authStatus";

  // Egress
  public static final String EGRESS_STATE = "egressState";
  public static final String EGRESS_STATUS = "egressStatus";

  // Session
  public static final String SESSION_STATE = "sessionState";
  public static final String SESSION_STATUS = "sessionStatus";
  public static final String SESSION_ACTIVE_TUN_FD = "sessionActiveTunFd";
  public static final String SESSION_ACTIVE_NETWORK_TYPE = "sessionActiveNetworkType";
  public static final String SESSION_PREVIOUS_TUN_FD = "sessionPreviousTunFd";
  public static final String SESSION_PREVIOUS_NETWORK_FD = "sessionPreviousNetworkFd";
  public static final String SESSION_PREVIOUS_NETWORK_TYPE = "sessionPreviousNetworkType";

  // Datapath
  public static final String DATAPATH_UPLINK_PACKETS_READ = "datapathUplinkPacketsRead";
  public static final String DATAPATH_DOWNLINK_PACKETS_READ = "datapathDownlinkPacketsRead";
  public static final String DATAPATH_UPLINK_PACKETS_DROPPED = "datapathUplinkPacketsDropped";
  public static final String DATAPATH_DOWNLINK_PACKETS_DROPPED = "datapathDownlinkPacketsDropped";
  public static final String DATAPATH_DECRYPTION_ERRORS = "datapathDecryptionErrors";

  // Health Check
  public static final String HEALTH_CHECK_RESULTS = "healthCheckResults";
  public static final String HEALTH_CHECK_SUCCESSFUL = "healthCheckSuccessful";
  public static final String NETWORK_SWITCHES_SINCE_HEALTH_CHECK =
      "networkSwitchesSinceHealthCheck";

  /** Creates a JSON representation of KryptonDebugInfo, as supplied by the cross-platform proto. */
  public static JSONObject fromProto(KryptonDebugInfo debugInfo) {
    JSONObject json = new JSONObject();

    Json.put(json, ZINC_URL, debugInfo.getConfig().getZincUrl());
    Json.put(json, BRASS_URL, debugInfo.getConfig().getBrassUrl());
    Json.put(json, SERVICE_TYPE, debugInfo.getConfig().getServiceType());
    Json.put(json, CANCELLED, debugInfo.getCancelled());

    if (debugInfo.hasReconnector()) {
      Json.put(json, RECONNECTOR_STATE, debugInfo.getReconnector().getState());
      Json.put(
          json, SESSION_RESTART_COUNTER, debugInfo.getReconnector().getSessionRestartCounter());
      Json.put(
          json,
          SUCCESSIVE_CONTROL_PLANE_FAILURES,
          debugInfo.getReconnector().getSuccessiveControlPlaneFailures());
      Json.put(
          json,
          SUCCESSIVE_DATA_PLANE_FAILURES,
          debugInfo.getReconnector().getSuccessiveDataPlaneFailures());
    }

    if (debugInfo.hasAuth()) {
      Json.put(json, AUTH_STATE, debugInfo.getAuth().getState());
      Json.put(json, AUTH_STATUS, debugInfo.getAuth().getStatus());
    }

    if (debugInfo.hasEgress()) {
      Json.put(json, EGRESS_STATE, debugInfo.getEgress().getState());
      Json.put(json, EGRESS_STATUS, debugInfo.getEgress().getStatus());
    }

    if (debugInfo.hasSession()) {
      Json.put(json, SESSION_STATE, debugInfo.getSession().getState());
      Json.put(json, SESSION_STATUS, debugInfo.getSession().getStatus());
      if (debugInfo.getSession().hasActiveTunFd()) {
        Json.put(json, SESSION_ACTIVE_TUN_FD, debugInfo.getSession().getActiveTunFd());
      }
      if (debugInfo.getSession().hasActiveNetwork()) {
        if (debugInfo.getSession().getActiveNetwork().hasNetworkType()) {
          Json.put(
              json,
              SESSION_ACTIVE_NETWORK_TYPE,
              debugInfo.getSession().getActiveNetwork().getNetworkType().name());
        }
      }
      if (debugInfo.getSession().hasPreviousTunFd()) {
        Json.put(json, SESSION_PREVIOUS_TUN_FD, debugInfo.getSession().getPreviousTunFd());
      }
      if (debugInfo.getSession().hasPreviousNetwork()) {
        if (debugInfo.getSession().getPreviousNetwork().hasNetworkType()) {
          Json.put(
              json,
              SESSION_PREVIOUS_NETWORK_TYPE,
              debugInfo.getSession().getPreviousNetwork().getNetworkType().name());
        }
      }
      if (debugInfo.getSession().hasDatapath()) {
        DatapathDebugInfo datapathDebugInfo = debugInfo.getSession().getDatapath();
        if (datapathDebugInfo.hasUplinkPacketsRead()) {
          Json.put(json, DATAPATH_UPLINK_PACKETS_READ, datapathDebugInfo.getUplinkPacketsRead());
        }
        if (datapathDebugInfo.hasDownlinkPacketsRead()) {
          Json.put(
              json, DATAPATH_DOWNLINK_PACKETS_READ, datapathDebugInfo.getDownlinkPacketsRead());
        }
        if (datapathDebugInfo.hasUplinkPacketsDropped()) {
          Json.put(
              json, DATAPATH_UPLINK_PACKETS_DROPPED, datapathDebugInfo.getUplinkPacketsDropped());
        }
        if (datapathDebugInfo.hasDownlinkPacketsDropped()) {
          Json.put(
              json,
              DATAPATH_DOWNLINK_PACKETS_DROPPED,
              datapathDebugInfo.getDownlinkPacketsDropped());
        }
        if (datapathDebugInfo.hasDecryptionErrors()) {
          Json.put(json, DATAPATH_DECRYPTION_ERRORS, datapathDebugInfo.getDecryptionErrors());
        }
        if (datapathDebugInfo.getHealthCheckResultsCount() != 0) {
          JSONArray healthCheckResults = new JSONArray();
          for (int i = 0; i < datapathDebugInfo.getHealthCheckResultsCount(); i++) {
            JSONObject singleHealthCheck = new JSONObject();
            Json.put(
                singleHealthCheck,
                HEALTH_CHECK_SUCCESSFUL,
                datapathDebugInfo.getHealthCheckResults(i).getHealthCheckSuccessful());
            Json.put(
                singleHealthCheck,
                NETWORK_SWITCHES_SINCE_HEALTH_CHECK,
                datapathDebugInfo.getHealthCheckResults(i).getNetworkSwitchesSinceHealthCheck());
            healthCheckResults.put(singleHealthCheck);
          }
          Json.put(json, HEALTH_CHECK_RESULTS, healthCheckResults);
        }
      }
    }

    return json;
  }
}
