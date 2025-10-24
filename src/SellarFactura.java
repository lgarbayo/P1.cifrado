import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SellarFactura {

    // Constantes para los nombres de los bloques
    private static final String BLOQUE_FACTURA_CIFRADA = "FACTURA_CIFRADA";
    private static final String BLOQUE_CLAVE_CIFRADA = "CLAVE_CIFRADA";
    private static final String BLOQUE_FIRMA_EMPRESA = "FIRMA_EMPRESA";
    private static final String BLOQUE_SELLO_TIEMPO = "SELLO_TIEMPO";
    private static final String BLOQUE_FIRMA_AUTORIDAD = "FIRMA_AUTORIDAD";

    // Algoritmos usados: RSA y SHA-512 (por el NIST en documentos de seguridad)
    private static final String ALGORITMO_FIRMA = "SHA512withRSA";
    private static final String PROVIDER = "BC";

    public static void main(String[] args) throws Exception {
        // [Paso 1.1] Verificar argumentos
        if (args.length != 3) {
            mensajeAyuda();
            System.exit(1);
        }

        String nombrePaquete = args[0];
        String ficheroClavePublicaEmpresa = args[1];
        String ficheroClavePrivadaAutoridad = args[2];

        // [Paso 1.2] Cargar el Provider BouncyCastle
        Security.addProvider(new BouncyCastleProvider());

        try {
            // [Paso 1.3] Cargar el Paquete de la Empresa
            Paquete paquete = new Paquete(nombrePaquete);

            // Si el paquete está sellado (contiene la firma de la autoridad), salimos
            if (paquete.getContenidoBloque(BLOQUE_FIRMA_AUTORIDAD) != null) {
                System.err.println("Error: El paquete ya ha sido sellado.");
                System.exit(1);
            }

            // Recuperar datos a verificar (los datos que cubrió la firma de la Empresa)
            byte[] facturaCifrada = paquete.getContenidoBloque(BLOQUE_FACTURA_CIFRADA);
            byte[] claveCifrada = paquete.getContenidoBloque(BLOQUE_CLAVE_CIFRADA);
            byte[] firmaEmpresa = paquete.getContenidoBloque(BLOQUE_FIRMA_EMPRESA);

            if (facturaCifrada == null || claveCifrada == null || firmaEmpresa == null) {
                System.err.println("Error: El paquete no contiene los bloques necesarios (Factura Cifrada, Clave Cifrada o Firma de la Empresa).");
                System.exit(1);
            }

            // Cargar Claves Criptográficas
            PublicKey clavePublicaEmpresa = cargarClavePublica(ficheroClavePublicaEmpresa);
            PrivateKey clavePrivadaAutoridad = cargarClavePrivada(ficheroClavePrivadaAutoridad);

            // Verificación de la Firma de la Empresa (R7)
            System.out.println("-> Verificando autenticidad de la Empresa...");

            // El mensaje a verificar es la concatenación de los contenidos críticos
            byte[] mensajeFirmadoEmpresa = concatenarBytes(facturaCifrada, claveCifrada);

            Signature verificadorEmpresa = Signature.getInstance(ALGORITMO_FIRMA, PROVIDER);
            verificadorEmpresa.initVerify(clavePublicaEmpresa);
            verificadorEmpresa.update(mensajeFirmadoEmpresa);

            if (!verificadorEmpresa.verify(firmaEmpresa)) {
                // Si la verificación falla, terminar.
                System.err.println("¡ERROR! La verificación de la firma de la Empresa falló.");
                System.err.println("El paquete no fue creado por la Empresa correspondiente o fue modificado.");
                System.exit(1);
            }
            System.out.println("-> Verificación de la firma de la Empresa: CORRECTA.");

            // Generación y Añadir el Sello de Tiempo (R6)
            System.out.println("-> Generando Sello de Tiempo...");

            // Generar timestamp en formato ISO 8601
            String timestampStr = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            byte[] selloTiempo = timestampStr.getBytes("UTF-8");

            // Añadir bloque de timestamp
            paquete.anadirBloque(BLOQUE_SELLO_TIEMPO, selloTiempo);
            System.out.println("   Sello de Tiempo añadido: " + timestampStr);

            // Firmar el Sello con la Autoridad (R6)
            System.out.println("-> Firmando el Sello de Tiempo y contenidos con la Autoridad...");

            // Lo que la Autoridad firma es el HASH del paquete COMPLETO de la Empresa + el TIMESTAMP
            // Nota: Para asegurar la integridad de la intervención de la Empresa (R6),
            // la Autoridad firma los datos originales (facturaCifrada + claveCifrada) Y la marca de tiempo.
            // Esto asegura que la fecha se asocia a *ese* contenido inalterado.
            byte[] mensajeAFirmarAutoridad = concatenarBytes(facturaCifrada, claveCifrada, selloTiempo);

            Signature firmadorAutoridad = Signature.getInstance(ALGORITMO_FIRMA, PROVIDER);
            firmadorAutoridad.initSign(clavePrivadaAutoridad);
            firmadorAutoridad.update(mensajeAFirmarAutoridad);
            byte[] firmaAutoridad = firmadorAutoridad.sign();

            // Añadir bloque de firma de la Autoridad
            paquete.anadirBloque(BLOQUE_FIRMA_AUTORIDAD, firmaAutoridad);
            System.out.println("-> Firma de la Autoridad añadida al paquete.");

            // Escritura y Finalización
            paquete.escribirPaquete(nombrePaquete);
            System.out.println("--------------------------------------------------------------------");
            System.out.println("ÉXITO: Factura Empaquetada sellada y guardada en " + nombrePaquete);
            System.out.println("--------------------------------------------------------------------");

        } catch (Exception e) {
            System.err.println("Error durante el sellado de la factura: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Muestra la sintaxis correcta.
     */
    public static void mensajeAyuda() {
        System.out.println("Sella una Factura Empaquetada por la Autoridad de Sellado.");
        System.out.println("\tSintaxis: java SellarFactura <nombre_paquete> <clave_publica_empresa> <clave_privada_autoridad>");
        System.out.println();
    }

    /**
     * Carga una clave pública RSA desde un fichero X509.
     * Basado en la lógica inversa de GenerarClaves.java.
     */
    public static PublicKey cargarClavePublica(String ficheroClave) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(ficheroClave)); // Leer el contenido del archivo binario
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA", PROVIDER);
        return kf.generatePublic(spec);
    }

    /**
     * Carga una clave privada RSA desde un fichero PKCS8.
     * Basado en la lógica inversa de GenerarClaves.java.
     */
    public static PrivateKey cargarClavePrivada(String ficheroClave) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(ficheroClave)); // Leer el contenido del archivo binario
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA", PROVIDER);
        return kf.generatePrivate(spec);
    }

    /**
     * Concatena arrays de bytes para generar el mensaje a firmar/verificar.
     */
    private static byte[] concatenarBytes(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }
}
