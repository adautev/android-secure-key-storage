package com.example.andrey.securekeystorage;

import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.TextView;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class MainActivity extends AppCompatActivity {

    public static final String STORAGE_AES_KEY = "STORAGE_AES_KEY";
    public static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    public static final String SHARED_PREFERENCES_FILE_KEY = "ContextSharedPreferences";
    public static final String SHARED_PREFERENCES_IV_KEY = "IV_KEY";
    protected static final int DEVICE_POLICY_INTENT_SET_PASSWORD = 2;
    private static final int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;

    private SecretKey key;
    private byte[] encryptedPayload;
    private SharedPreferences.Editor sharedPreferencesEditor;
    private SharedPreferences sharedPreferences;
    private KeyguardManager keyguardManager;
    private boolean keyGuardManagerInsecure;

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);
        setContentView(R.layout.activity_main);
        handleDeviceSecurity();
        Context context = getApplication().getApplicationContext();
        this.sharedPreferences = context.getSharedPreferences(SHARED_PREFERENCES_FILE_KEY, Context.MODE_PRIVATE);
        sharedPreferencesEditor = sharedPreferences.edit();
        handleScreenState();
    }
    private void handleScreenState() {
        if(!this.keyGuardManagerInsecure) {
            try {
                if (extractKeyFromKeyStore() == null) {
                    findViewById(R.id.generate).setEnabled(true);
                    findViewById(R.id.extract).setEnabled(false);
                } else {
                    findViewById(R.id.generate).setEnabled(false);
                    findViewById(R.id.extract).setEnabled(true);
                }
                findViewById(R.id.decrypt).setEnabled(this.encryptedPayload!=null);
                findViewById(R.id.encrypt).setEnabled(false);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (UnrecoverableEntryException e) {
                e.printStackTrace();
            }
        } else {
            findViewById(R.id.generate).setEnabled(false);
            findViewById(R.id.extract).setEnabled(false);
            findViewById(R.id.decrypt).setEnabled(this.encryptedPayload!=null);
            findViewById(R.id.encrypt).setEnabled(false);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    private void handleDeviceSecurity() {
        this.keyGuardManagerInsecure = !this.keyguardManager.isKeyguardSecure();
        if(keyGuardManagerInsecure) {
            Intent setPasswordIntent = new Intent(
                    DevicePolicyManager.ACTION_SET_NEW_PASSWORD);
            startActivityForResult(setPasswordIntent, DEVICE_POLICY_INTENT_SET_PASSWORD);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.N)
    public void generateKey(View view) {
        try {
            final KeyGenerator keyGenerator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(STORAGE_AES_KEY,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                //This one is quite useful towards UX, but requires Android 7.0 at least
                .setUserAuthenticationValidityDurationSeconds(30)
                .setUserAuthenticationRequired(true)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build();
            keyGenerator.init(keyGenParameterSpec);
            this.key = keyGenerator.generateKey();
            findViewById(R.id.generate).setEnabled(false);
            findViewById(R.id.extract).setEnabled(true);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    public void extractKey(View view) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableEntryException {
        this.key = extractKeyFromKeyStore();
        if(this.key != null) {
            findViewById(R.id.encrypt).setEnabled(true);
        }
    }

    private SecretKey extractKeyFromKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(STORAGE_AES_KEY, null);
        if(secretKeyEntry == null) {
            return null;
        }
        return secretKeyEntry.getSecretKey();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void encrypt(View view) throws InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        try {

            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, this.key);
            this.encryptedPayload = cipher.doFinal("Hello world!".getBytes("UTF-8"));
            this.setIV(cipher.getIV());
            ((TextView)findViewById(R.id.text)).setText(R.string.main_activity_encrypted_message);
            findViewById(R.id.decrypt).setEnabled(true);
        } catch (UserNotAuthenticatedException e) {
            // User is not authenticated, let's authenticate with device credentials.
            showAuthenticationScreen();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void decrypt(View view) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        try {
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            final GCMParameterSpec spec = new GCMParameterSpec(128, getIV());
            cipher.init(Cipher.DECRYPT_MODE, this.key, spec);
            String decryptedPayload = new String(cipher.doFinal(this.encryptedPayload), "UTF-8");
            ((TextView)findViewById(R.id.text)).setText(getString(R.string.main_activity_decrypted_payload_prefix) + decryptedPayload);
        } catch (UserNotAuthenticatedException e) {
            // User is not authenticated, let's authenticate with device credentials.
            showAuthenticationScreen();
        }

    }

    public void resetKey(View view) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
        keyStore.deleteEntry(STORAGE_AES_KEY);
        findViewById(R.id.generate).setEnabled(true);
        findViewById(R.id.extract).setEnabled(false);
        findViewById(R.id.decrypt).setEnabled(false);
        findViewById(R.id.encrypt).setEnabled(false);
    }

    public byte[] getIV() {
        String encodedIv = sharedPreferences.getString(SHARED_PREFERENCES_IV_KEY, "");
        return android.util.Base64.decode(encodedIv, android.util.Base64.DEFAULT);
    }

    public void setIV(byte[] IV) {
        String encoded = Base64.encodeToString(IV, Base64.DEFAULT);
        sharedPreferencesEditor.putString(SHARED_PREFERENCES_IV_KEY, encoded);
        sharedPreferencesEditor.commit();
    }
    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    private void showAuthenticationScreen() {
        // Create the Confirm Credentials screen. You can customize the title and description. Or
        // we will provide a generic one for you if you leave it null
        Intent intent = keyguardManager.createConfirmDeviceCredentialIntent(null, null);
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN)
    @Override
    protected void onResume() {
        super.onResume();
        handleDeviceSecurity();
        handleScreenState();
    }
}
