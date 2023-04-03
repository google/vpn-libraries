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

package com.google.android.libraries.privacy.ppn.internal.json;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** A collection of helpers for dealing with JSON. */
public class Json {
  private Json() {}

  /**
   * Puts a (key, value) pair into a json object while swallowing the impossible checked exception.
   * (JSONObject.put() can only throw if passed infinity or NaN as a value.)
   */
  public static void put(JSONObject json, String key, String value) {
    try {
      json.put(key, value);
    } catch (JSONException impossible) {
      // put cannot throw if the value is a String.
      throw new AssertionError(impossible);
    }
  }

  /**
   * Puts a (key, value) pair into a json object while swallowing the impossible checked exception.
   * (JSONObject.put() can only throw if passed infinity or NaN as a value.)
   */
  public static void put(JSONObject json, String key, int value) {
    try {
      json.put(key, value);
    } catch (JSONException impossible) {
      // put cannot throw if the value is an int.
      throw new AssertionError(impossible);
    }
  }

  /**
   * Puts a (key, value) pair into a json object while swallowing the impossible checked exception.
   * (JSONObject.put() can only throw if passed infinity or NaN as a value.)
   */
  public static void put(JSONObject json, String key, long value) {
    try {
      json.put(key, value);
    } catch (JSONException impossible) {
      // put cannot throw if the value is an int.
      throw new AssertionError(impossible);
    }
  }

  /**
   * Puts a (key, value) pair into a json object while swallowing the impossible checked exception.
   * (JSONObject.put() can only throw if passed infinity or NaN as a value.)
   */
  public static void put(JSONObject json, String key, boolean value) {
    try {
      json.put(key, value);
    } catch (JSONException impossible) {
      // put cannot throw if the value is a boolean.
      throw new AssertionError(impossible);
    }
  }

  /**
   * Puts a (key, value) pair into a json object while swallowing the impossible checked exception.
   * (JSONObject.put() can only throw if passed infinity or NaN as a value.)
   */
  public static void put(JSONObject json, String key, JSONObject value) {
    try {
      json.put(key, value);
    } catch (JSONException impossible) {
      // put cannot throw if the value is an object.
      throw new AssertionError(impossible);
    }
  }

  /**
   * Puts a (key, value) pair into a json object while swallowing the impossible checked exception.
   * (JSONObject.put() can only throw if passed infinity or NaN as a value.)
   */
  public static void put(JSONObject json, String key, JSONArray value) {
    try {
      json.put(key, value);
    } catch (JSONException impossible) {
      // put cannot throw if the value is an array.
      throw new AssertionError(impossible);
    }
  }
}
