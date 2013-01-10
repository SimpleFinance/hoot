/*
 * Copyright (C) 2013 Simple Finance Technology Ltd.
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

package com.twotoasters.android.hoot;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.http.conn.ssl.SSLSocketFactory;

import android.content.Context;
import android.util.Log;

public class HootPinnedCerts {
  private final KeyStore keyStore;
  private final TrustManager[] trustManagers;

  public HootPinnedCerts(Context context, String... names) throws Exception {
    keyStore = KeyStore.getInstance("BKS");
    keyStore.load(null, null);
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    
    int i = 0;
    for (String name : names) {
      Certificate cert = certificateFactory.generateCertificate(context.getAssets().open(name));
      keyStore.setCertificateEntry("trusted-" + Integer.toString(i++), cert);
    }
    
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("X509");
    trustManagerFactory.init(keyStore);
    trustManagers = trustManagerFactory.getTrustManagers();
  }
  
  public SSLSocketFactory getApacheSslSocketFactory() {
    try {
      return new SSLSocketFactory(keyStore);
    } catch (GeneralSecurityException e) {
      Log.e("HOOT", "Error initializing pinned SSL factory. Using default.");
      return SSLSocketFactory.getSocketFactory();
    }
  }

  /**
   * @return null on failure.
   */
  public javax.net.ssl.SSLSocketFactory getSslSocketFactory() {
    try {
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, trustManagers, null);
      return sslContext.getSocketFactory();
    } catch (GeneralSecurityException e) {
      Log.e("HOOT", "Error initializing pinned SSL factory. Using default.");
      return null;
    }
  }
}
