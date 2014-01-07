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

import android.content.Context;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Handles certificate pinning for secure HTTPS requests for use with
 * {@link com.twotoasters.android.hoot.Hoot}.
 * <p/>
 * Loads public keys encoded in the {@code DER} format from the application's assets directory.
 */
public class HootPinnedCerts {
    private final SSLSocketFactory mSecureSocketFactory;

    public HootPinnedCerts(Context context, String... paths) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException, KeyManagementException {
        final Set<PublicKey> keys = new HashSet<PublicKey>();
        for (String p : paths) {
            keys.add(getPubKey(context, p));
        }

        // Initialize our sole TrustManager
        TrustManager[] tm = { new PubKeyManager(keys) };

        // Initialize our secure socket factory
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tm, null);
        mSecureSocketFactory = sslContext.getSocketFactory();
    }

    /**
     * Returns an {@link javax.net.ssl.SSLSocketFactory} constructed with the
     * {@link PubKeyManager} as the sole {@link javax.net.ssl.TrustManager}.
     */
    public SSLSocketFactory getSslSocketFactory() {
        return mSecureSocketFactory;
    }

    /**
     * Returns a public key loaded from the given path relative to the assets directory.
     * <p/>
     * The key must be stored in the {@code DER} format.
     */
    private static PublicKey getPubKey(Context context, String path) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream in = context.getAssets().open(path);

        // Read the key file
        byte[] bytes = new byte[in.available()];
        in.read(bytes);
        in.close();

        // Load the public key
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    /**
     * Manages public key pinning for use with an {@link javax.net.ssl.HttpsURLConnection}.
     * <p/>
     * Based on samples from
     * <a href="https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#Android">owasp.org</a>.
     */
    private static class PubKeyManager implements X509TrustManager {
        private final Set<PublicKey> mPubKeys =
                new HashSet<PublicKey>();

        public PubKeyManager(Set<PublicKey> keys) {
            if (keys == null) {
                throw new IllegalArgumentException("key set is null");
            }
            mPubKeys.addAll(keys);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            throw new UnsupportedOperationException("getAcceptedIssuers not supported");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new UnsupportedOperationException("checkClientTrusted not supported");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            if (chain == null) {
                throw new IllegalArgumentException("X509Certificate array is null");
            }

            if (!(chain.length > 0)) {
                throw new IllegalArgumentException("X509Certificate is empty");
            }

            if (!(null != authType && authType.equalsIgnoreCase("RSA"))) {
                throw new CertificateException("authType is not RSA");
            }

            // Perform customary SSL/TLS checks
            try {
                TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
                tmf.init((KeyStore) null);

                for (TrustManager trustManager : tmf.getTrustManagers()) {
                    ((X509TrustManager) trustManager).checkServerTrusted(chain, authType);
                }
            } catch (Exception e) {
                throw new CertificateException(e);
            }

            PublicKey pubKey = chain[0].getPublicKey();
            if (!mPubKeys.contains(pubKey)) {
                throw new CertificateException("Invalid public key: " + pubKey.toString());
            }
        }
    }
}
