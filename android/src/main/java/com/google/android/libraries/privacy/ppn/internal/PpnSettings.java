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

package com.google.android.libraries.privacy.ppn.internal;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;

/** Settings that persisted across App restart */
public class PpnSettings {
  private static final String ACCOUNT_NAME = "AccountName";

  private static final String SHARED_PREFS_KEY =
      "com.google.android.libraries.privacy.ppn.Settings";

  private final SharedPreferences sharedPreferences;

  // Context could be ActivityContext or ApplicationContext.
  public PpnSettings(Context context) {
    // Use a PREFERENCE_KEY other than the shared default preference file.
    sharedPreferences =
        context
            .getApplicationContext()
            .getSharedPreferences(SHARED_PREFS_KEY, Context.MODE_PRIVATE);
  }

  private void setStringSetting(String key, String value) {
    Editor editor = sharedPreferences.edit();
    editor.putString(key, value);
    editor.apply();
  }

  private void removeSetting(String key) {
    Editor editor = sharedPreferences.edit();
    editor.remove(key);
    editor.apply();
  }

  public void setAccountName(String accountName) {
    setStringSetting(ACCOUNT_NAME, accountName);
  }

  public String getAccountName() {
    return sharedPreferences.getString(ACCOUNT_NAME, null);
  }

  public void removeAccountName() {
    removeSetting(ACCOUNT_NAME);
  }
}
