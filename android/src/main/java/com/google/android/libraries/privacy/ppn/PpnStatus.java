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

package com.google.android.libraries.privacy.ppn;

import java.util.HashMap;
import java.util.Map;

/** Java representation of C++ absl::Status. */
public class PpnStatus {
  public static final PpnStatus STATUS_OK = new PpnStatus(Code.OK, "");

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
   * Construct an Status with int and message. In case the code is out of range of code, the code
   * will be set to UNKNOWN. Message cannot be null.
   */
  public PpnStatus(int code, String message) {
    this.code = Code.fromCode(code);
    this.message = message;
  }

  /** Construct an Status with code and message. Message cannot be null */
  public PpnStatus(Code code, String message) {
    this.code = code;
    this.message = message;
  }

  public Code getCode() {
    return code;
  }

  public String getMessage() {
    return message;
  }

  @Override
  public String toString() {
    return code.toString() + ":" + message;
  }

  private final Code code;
  private final String message;
}
