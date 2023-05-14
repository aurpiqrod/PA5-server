package com.insegus.pai5;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import org.json.JSONObject;

import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.net.ssl.*;

public class App {
    private static boolean verifySignature(String data, String signature) {
        try {
            // Cargar el certificado público del cliente desde el archivo del certificado
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            FileInputStream certificateFile = new FileInputStream(App.class.getResource("/keystore/client_certificate.crt").getPath());
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certificateFile);
    
            // Obtener la clave pública del certificado
            PublicKey publicKey = certificate.getPublicKey();
    
            // Crear una instancia del objeto Signature y configurarlo para la verificación
            Signature signatureInstance = Signature.getInstance("SHA256withRSA");
            signatureInstance.initVerify(publicKey);
    
            // Actualizar la instancia de la firma con los datos de la solicitud
            signatureInstance.update(data.getBytes("UTF-8"));
    
            // Decodificar la firma en Base64
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
    
            // Verificar la firma
            boolean isSignatureValid = signatureInstance.verify(signatureBytes);
    
            return isSignatureValid;
        } catch (Exception e) {
            e.printStackTrace();
        }
    
        return false;
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        try {
            // Obtener la ruta del archivo del keystore y su contraseña desde las
            // propiedades del sistema
            String keystorePassword = "password";
            String keystorePath = App.class.getResource("/keystore/keystore.jks").getPath();

            // Cargar el keystore desde la ruta y la contraseña proporcionadas
            KeyStore keystore = KeyStore.getInstance("JKS");
            FileInputStream keystoreFile = new FileInputStream(keystorePath);
            keystore.load(keystoreFile, keystorePassword.toCharArray());

            // Crear un SSLContext y un SSLServerSocketFactory a partir del keystore cargado
            SSLContext sslContext = SSLContext.getInstance("TLS");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keystore, keystorePassword.toCharArray());
            sslContext.init(kmf.getKeyManagers(), null, null);
            SSLServerSocketFactory factory = sslContext.getServerSocketFactory();

            // Crear un SSLServerSocket en el puerto 7070
            SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(7070);

            // Configurar parámetros de seguridad SSL/TLS en el servidor SSL
            SSLParameters sslParams = new SSLParameters();
            String[] protocols = new String[] { "TLSv1.3" };
            String[] cipherSuites = new String[] {
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256"
            };
            sslParams.setProtocols(protocols);
            sslParams.setCipherSuites(cipherSuites);
            serverSocket.setSSLParameters(sslParams);

            while (true) {
                System.err.println("Waiting for connection...");

                // Esperar y aceptar conexiones de clientes
                SSLSocket socket = (SSLSocket) serverSocket.accept();

                // Abrir BufferedReader para leer datos del cliente
                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));

                // Leer la petición completa del cliente
                String clientRequest = input.readLine();
                System.out.println("Petición recibida: " + clientRequest);

                // Parsear la petición del cliente como un objeto JSON
                JSONObject requestData = new JSONObject(clientRequest);

                // Extraer y mostrar los datos del objeto JSON
                System.out.println("Datos del cliente: " + requestData.toString(2));

                // Obtener la firma de la solicitud
                String signature = requestData.optString("signature");

                if (signature != null) {
                    // Verificar la firma utilizando el certificado público del cliente
                    boolean isSignatureValid = verifySignature(requestData.toString(), signature);

                    if (isSignatureValid) {
                        // La firma es válida, proceder con el procesamiento de la solicitud
                        // ...
                        // Resto del código de procesamiento de la solicitud
                    } else {
                        // La firma no es válida, rechazar la solicitud
                        System.out.println("La firma de la solicitud no es válida. La solicitud será rechazada.");
                    }
                } else {
                    // No se proporcionó una firma, rechazar la solicitud
                    System.out.println("La solicitud no está firmada. La solicitud será rechazada.");
                }

                // Extraer y mostrar los datos del objeto JSON
                System.out.println("Datos del cliente: " + requestData.toString(2));

                // Abrir PrintWriter para enviar datos al cliente
                PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));

                // Enviar una respuesta al cliente
                output.println("Petición recibida y procesada.");
                output.flush(); // Asegúrate de que la respuesta se envíe antes de cerrar los recursos

                // Cerrar recursos
                output.close();
                input.close();
                socket.close();
            }

        } catch (IOException | KeyStoreException | NoSuchAlgorithmException
                | CertificateException | UnrecoverableKeyException | KeyManagementException ex) {
            System.err.println("Error: " + ex.getMessage());
            ex.printStackTrace();
        }
    }
}