package com.insegus.pai5;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.Date;
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
import java.util.Properties;

import javax.net.ssl.*;

public class App {
    private static X509Certificate getClientCertificate(String clientCertPath) {
        try {
            // Cargar el certificado público del cliente desde el archivo del certificado
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            FileInputStream certificateFile = new FileInputStream(App.class.getResource(clientCertPath).getPath());
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certificateFile);
            //System.out.println("Certificado del cliente: " + certificate.toString());
            return certificate;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static boolean verifySignature(String data, String signature, X509Certificate certificate) {        
        try {
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
            // Cargar las propiedades desde el archivo de configuración
            Properties properties = new Properties();
            FileInputStream configFile = new FileInputStream(
                    App.class.getResource("/config/config.properties").getPath());
            properties.load(new InputStreamReader(configFile));

            // Obtener las contraseñas y rutas de los recursos desde las propiedades
            // cargadas
            String keystorePassword = properties.getProperty("keystorePassword");
            String truststorePassword = properties.getProperty("truststorePassword");
            String keystorePath = App.class.getResource(properties.getProperty("keystorePath")).getPath();
            String truststorePath = App.class.getResource(properties.getProperty("truststorePath")).getPath();
            String clientCertPath = properties.getProperty("clientCertPath");

            // Cargar el keystore y truststore desde las rutas y contraseñas proporcionadas
            KeyStore keystore = KeyStore.getInstance("JKS");
            FileInputStream keystoreFile = new FileInputStream(keystorePath);
            keystore.load(keystoreFile, keystorePassword.toCharArray());

            KeyStore truststore = KeyStore.getInstance("JKS");
            FileInputStream truststoreFile = new FileInputStream(truststorePath);
            truststore.load(truststoreFile, truststorePassword.toCharArray());

            // Crear un SSLContext y un SSLServerSocketFactory a partir del keystore y
            // truststore cargados
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keystore, keystorePassword.toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(truststore);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
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
            // Crear el archivo CSV si no existe y agregar encabezados
            String csvFileName = "requests.csv";
            if (!Files.exists(Paths.get(csvFileName))) {
                Files.write(Paths.get(csvFileName), "Date,Client,Request,Result\n".getBytes(),
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }

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
                // System.out.println("Datos del cliente: " + requestData.toString(2));

                // Obtener la firma de la solicitud
                String signature = requestData.optString("signature");
                boolean isSignatureValid = false;
                X509Certificate clientCertificate = getClientCertificate(clientCertPath);

                if (signature != null) {
                    // Verificar la firma utilizando el certificado público del cliente
                    requestData.remove("signature");
                    isSignatureValid = verifySignature(requestData.toString(), signature, clientCertificate);

                    if (isSignatureValid) {
                        // La firma es válida, proceder con el procesamiento de la solicitud
                        System.out.println("La firma de la solicitud es válida. La solicitud será guardada.");
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
                String response = isSignatureValid ? "Petición OK" : "Petición INCORRECTA";
                // Enviar una respuesta al cliente
                output.println(response);
                output.flush();
                // Extraer información del certificado del cliente
                String clientInfo = clientCertificate.getSubjectX500Principal().getName();

                // Obtener la fecha y hora actual
                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                String currentDate = dateFormat.format(new Date());

                // Guardar la petición en el archivo CSV
                String csvEntry = String.format("%s,%s,\"%s\",%s\n", currentDate, clientInfo, clientRequest, response);
                Files.write(Paths.get(csvFileName), csvEntry.getBytes(), StandardOpenOption.APPEND);

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