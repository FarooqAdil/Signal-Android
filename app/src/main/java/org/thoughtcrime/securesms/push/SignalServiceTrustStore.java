package org.thoughtcrime.securesms.push;

import android.content.Context;

import org.thoughtcrime.securesms.R;
import org.signal.network.config.TrustStore;

import java.io.InputStream;

// MSc Research - TLS-Proxy-Modification:
import org.thoughtcrime.securesms.BuildConfig;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public class SignalServiceTrustStore implements TrustStore {

  private final Context context;

  public SignalServiceTrustStore(Context context) {
    this.context = context.getApplicationContext();
  }

  @Override
  public InputStream getKeyStoreInputStream() {
    // Only augment the Signal trust store in debug builds; otherwise return the original trust store
    if (!BuildConfig.DEBUG) {
      return context.getResources().openRawResource(R.raw.whisper);
    }

    try {
      // Creates a keystore and loads the Signal whisper BKS trust store
      KeyStore keyStore = KeyStore.getInstance("BKS");
      try (InputStream inputStream = context.getResources().openRawResource(R.raw.whisper)) {
        keyStore.load(inputStream, getKeyStorePassword().toCharArray());
      }

      // Loads the Burp CA as an X.509 certificate and adds it to the keystore
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

      try (InputStream certificateInputStream =
               context.getResources().openRawResource(R.raw.burp_portswigger_ca)) {
        Certificate burpCa = certificateFactory.generateCertificate(certificateInputStream);
        keyStore.setCertificateEntry("burp-portswigger-ca", burpCa);
      }

      // Serializes and returns the keystore as a byte stream, as specified by the function
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      keyStore.store(outputStream, getKeyStorePassword().toCharArray());

      return new ByteArrayInputStream(outputStream.toByteArray());

    } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
      throw new AssertionError(e);
    }
  }

  @Override
  public String getKeyStorePassword() {
    return "whisper";
  }
}
