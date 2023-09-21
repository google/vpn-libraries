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

package com.google.android.libraries.privacy.ppn;

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import java.util.HashMap;
import java.util.Map;

/** Java representation of C++ absl::Status. */
public class PpnStatus {
  public static final String DETAILS_TYPE_URL = "type.googleapis.com/privacy.ppn.PpnStatusDetails";
  public static final PpnStatus STATUS_OK = new PpnStatus.Builder(Code.OK, "").build();

  /**
   * Java representation of absl::StatusCode as defined in
   * https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto#L26
   */
  public enum Code {
    OK(0),
    CANCELLED(1),
    UNKNOWN(2),
    INVALID_ARGUMENT(3),
    DEADLINE_EXCEEDED(4),
    NOT_FOUND(5),
    ALREADY_EXISTS(6),
    PERMISSION_DENIED(7),
    RESOURCE_EXHAUSTED(8),
    FAILED_PRECONDITION(9),
    ABORTED(10),
    OUT_OF_RANGE(11),
    UNIMPLEMENTED(12),
    INTERNAL(13),
    UNAVAILABLE(14),
    DATA_LOSS(15),
    UNAUTHENTICATED(16);

    private final int value;

    private static final Map<Integer, Code> lookupMap = new HashMap<>();

    static {
      for (Code s : Code.values()) {
        lookupMap.put(s.getCode(), s);
      }
    }

    private Code(int value) {
      this.value = value;
    }

    /** Returns the int value of the Enum. */
    public int getCode() {
      return this.value;
    }

    public static Code fromCode(int code) {
      return lookupMap.getOrDefault(code, UNKNOWN);
    }
  }

  /**
   * A detailed error code for specific error cases we want to expose beyond the standard error
   * codes above.
   */
  public enum DetailedErrorCode {
    UNKNOWN(0),
    DISALLOWED_COUNTRY(1);

    private final int value;

    private static final Map<Integer, DetailedErrorCode> lookupMap = new HashMap<>();

    static {
      for (DetailedErrorCode s : DetailedErrorCode.values()) {
        lookupMap.put(s.getCode(), s);
      }
    }

    private DetailedErrorCode(int value) {
      this.value = value;
    }

    /** Returns the int value of the Enum. */
    public int getCode() {
      return this.value;
    }

    public static DetailedErrorCode fromCode(int code) {
      return lookupMap.getOrDefault(code, UNKNOWN);
    }
  }

  private final Code code;
  private final String message;
  private final DetailedErrorCode detailedErrorCode;

  /** A Builder for constructing PpnStatus objects. */
  public static class Builder {
    private final Code code;
    private final String message;
    private DetailedErrorCode detailedErrorCode = DetailedErrorCode.UNKNOWN;

    /**
     * Creates a Builder with int and message. In case the code is out of range of code, the code
     * will be set to UNKNOWN. Message cannot be null.
     */
    public Builder(int code, String message) {
      this.code = Code.fromCode(code);
      this.message = message;
    }

    /** Creates a Builder with code and message. Message cannot be null. */
    public Builder(Code code, String message) {
      this.code = code;
      this.message = message;
    }

    public PpnStatus build() {
      return new PpnStatus(this);
    }

    @CanIgnoreReturnValue
    public Builder setDetailedErrorCode(DetailedErrorCode code) {
      this.detailedErrorCode = code;
      return this;
    }
  }

  /**
   * Construct an Status with int and message. In case the code is out of range of code, the code
   * will be set to UNKNOWN. Message cannot be null.
   *
   * <p>Deprecated -- Use the Builder instead.
   */
  @Deprecated
  public PpnStatus(int code, String message) {
    this.code = Code.fromCode(code);
    this.message = message;
    this.detailedErrorCode = DetailedErrorCode.UNKNOWN;
  }

  /**
   * Construct an Status with code and message. Message cannot be null.
   *
   * <p>Deprecated -- Use the Builder instead.
   */
  @Deprecated
  public PpnStatus(Code code, String message) {
    this.code = code;
    this.message = message;
    this.detailedErrorCode = DetailedErrorCode.UNKNOWN;
  }

  private PpnStatus(Builder builder) {
    this.code = builder.code;
    this.message = builder.message;
    this.detailedErrorCode = builder.detailedErrorCode;
  }

  public Code getCode() {
    return code;
  }

  public String getMessage() {
    return message;
  }

  public DetailedErrorCode getDetailedErrorCode() {
    return detailedErrorCode;
  }

  @Override
  public String toString() {
    return code.toString() + ":" + message;
  }
}
