import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarFactura {

    private static final String BLOQUE_FACTURA_CIFRADA = "FACTURA_CIFRADA";
    private static final String BLOQUE_CLAVE_CIFRADA = "CLAVE_CIFRADA";
    private static final String BLOQUE_FIRMA_EMPRESA = "FIRMA_EMPRESA";
    private static final String BLOQUE_SELLO_TIEMPO = "SELLO_TIEMPO";
    private static final String BLOQUE_FIRMA_AUTORIDAD = "FIRMA_AUTORIDAD";

    private static final String ALGORITMO_FIRMA = "SHA512withRSA";
    private static final String ALGORITMO_CLAVE_SIMETRICA = "AES"; // Se asume AES para el cifrado de la factura
    private static final String MODO_CIFRADO_SIMETRICO = "AES/ECB/PKCS5Padding"; // Asumimos un modo de cifrado simple
    private static final String PROVIDER = "BC";
    // -----------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            mensajeAyuda();
            System.exit(1);
        }

        String nombrePaquete = args[0];
        String ficheroJsonSalida = args[1];
        String ficheroClavePrivadaHacienda = args[2];
        String ficheroClavePublicaEmpresa = args[3];
        String ficheroClavePublicaAutoridad = args[4];

        Security.addProvider(new BouncyCastleProvider());
        boolean todoCorrecto = true; // Flag para rastrear si todas las comprobaciones son correctas

        try {
            Paquete paquete = new Paquete(nombrePaquete);

            // Cargar Contenidos y Claves
            byte[] facturaCifrada = paquete.getContenidoBloque(BLOQUE_FACTURA_CIFRADA);
            byte[] claveCifrada = paquete.getContenidoBloque(BLOQUE_CLAVE_CIFRADA);
            byte[] firmaEmpresa = paquete.getContenidoBloque(BLOQUE_FIRMA_EMPRESA);
            byte[] selloTiempo = paquete.getContenidoBloque(BLOQUE_SELLO_TIEMPO);
            byte[] firmaAutoridad = paquete.getContenidoBloque(BLOQUE_FIRMA_AUTORIDAD);

            if (facturaCifrada == null || claveCifrada == null || firmaEmpresa == null || selloTiempo == null || firmaAutoridad == null) {
                System.err.println("¡ERROR CRÍTICO! El paquete está incompleto. Faltan bloques de Empresa y/o Autoridad.");
                System.exit(1);
            }

            PublicKey clavePublicaEmpresa = cargarClavePublica(ficheroClavePublicaEmpresa);
            PublicKey clavePublicaAutoridad = cargarClavePublica(ficheroClavePublicaAutoridad);
            PrivateKey clavePrivadaHacienda = cargarClavePrivada(ficheroClavePrivadaHacienda);

            System.out.println("--------------------------------------------------------------------");
            System.out.println("COMIENZAN LAS COMPROBACIONES DE LA FACTURA EMPAQUETADA:");
            System.out.println("--------------------------------------------------------------------");

            // -----------------------------------------------------------------------------------
            // 2. Verificación de la Firma de la Autoridad (Integridad y No Repudio del Sello) (R5, R6)
            // -----------------------------------------------------------------------------------
            System.out.println("1. Verificando Sello de la Autoridad de Sellado...");
            byte[] mensajeAFirmarAutoridad = concatenarBytes(facturaCifrada, claveCifrada, selloTiempo);

            Signature verificadorAutoridad = Signature.getInstance(ALGORITMO_FIRMA, PROVIDER);
            verificadorAutoridad.initVerify(clavePublicaAutoridad);
            verificadorAutoridad.update(mensajeAFirmarAutoridad);

            if (verificadorAutoridad.verify(firmaAutoridad)) {
                System.out.println("   -> Firma de la Autoridad: VÁLIDA.");
                String timestampStr = new String(selloTiempo, "UTF-8");
                System.out.println("   -> Sello de Tiempo (Timestamp): " + timestampStr);
            } else {
                System.out.println("   -> Firma de la Autoridad: ¡FALLIDA! El Sello de Tiempo o los datos originales fueron alterados. [cite: 696, 697]");
                todoCorrecto = false;
            }

            // Verificación de la Firma de la Empresa (Autenticidad) (R7)
            System.out.println("\n2. Verificando Firma de la Empresa...");
            byte[] mensajeFirmadoEmpresa = concatenarBytes(facturaCifrada, claveCifrada);

            Signature verificadorEmpresa = Signature.getInstance(ALGORITMO_FIRMA, PROVIDER);
            verificadorEmpresa.initVerify(clavePublicaEmpresa);
            verificadorEmpresa.update(mensajeFirmadoEmpresa);

            if (verificadorEmpresa.verify(firmaEmpresa)) {
                System.out.println("   -> Firma de la Empresa: VÁLIDA. (Procedencia de la Empresa correcta) [cite: 642]");
            } else {
                System.out.println("   -> Firma de la Empresa: ¡FALLIDA! El contenido de la Empresa fue alterado o la clave pública es incorrecta. [cite: 696]");
                todoCorrecto = false;
            }

            // Descifrado de la Factura (R1)
            String facturaClaro = null;

            if (todoCorrecto) {
                System.out.println("\n3. Descifrando Factura...");

                // Descifrar la clave simétrica con la clave privada de Hacienda (RSA)
                SecretKey claveSimetrica = descifrarClaveSimetrica(claveCifrada, clavePrivadaHacienda);

                // Descifrar la Factura con la clave simétrica (AES)
                facturaClaro = descifrarFactura(facturaCifrada, claveSimetrica);

                // Escritura y Finalización
                Files.write(Paths.get(ficheroJsonSalida), facturaClaro.getBytes("UTF-8"));

                System.out.println("   -> Descifrado completo. Factura original guardada en: " + ficheroJsonSalida + " [cite: 698]");
                System.out.println("--------------------------------------------------------------------");
                System.out.println("RESULTADO FINAL: TODAS LAS COMPROBACIONES CORRECTAS.");
                System.out.println("--------------------------------------------------------------------");
            } else {
                System.out.println("\nRESULTADO FINAL: COMPROBACIONES FALLIDAS. La Factura en Claro no será generada. [cite: 637]");
                System.out.println("--------------------------------------------------------------------");
            }

        } catch (Exception e) {
            System.err.println("\nError fatal durante el desempaquetado: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Descifra la clave simétrica (cifrada con RSA) para obtener el objeto SecretKey.
     */
    private static SecretKey descifrarClaveSimetrica(byte[] claveCifrada, PrivateKey krHacienda) throws Exception {
        Cipher descifradorRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding", PROVIDER);
        descifradorRSA.init(Cipher.UNWRAP_MODE, krHacienda);

        // Asumimos que la clave simétrica es AES de 128 bits (16 bytes)
        Key claveDesenvuelta = descifradorRSA.unwrap(claveCifrada, ALGORITMO_CLAVE_SIMETRICA, Cipher.SECRET_KEY);

        if (claveDesenvuelta instanceof SecretKey) {
            return (SecretKey) claveDesenvuelta;
        } else {
            throw new GeneralSecurityException("Clave simétrica descifrada no es un objeto SecretKey válido.");
        }
    }

    /**
     * Descifra la Factura (cifrada con AES) usando la clave simétrica.
     */
    private static String descifrarFactura(byte[] facturaCifrada, SecretKey claveSimetrica) throws Exception {
        Cipher descifradorAES = Cipher.getInstance(MODO_CIFRADO_SIMETRICO, PROVIDER);
        descifradorAES.init(Cipher.DECRYPT_MODE, claveSimetrica);

        byte[] facturaBytes = descifradorAES.doFinal(facturaCifrada);
        return new String(facturaBytes, "UTF-8");
    }

    // MÉTODOS AUXILIARES (deben ser incluidos en el archivo)

    /**
     * Muestra la sintaxis correcta.
     */
    public static void mensajeAyuda() {
        System.out.println("Desempaqueta y verifica una Factura Sellada en Hacienda.");
        System.out.println("\tSintaxis: java DesempaquetarFactura <paquete_sellado> <fichero_json_salida> <clave_privada_hacienda> <clave_publica_empresa> <clave_publica_autoridad>");
        System.out.println();
    }

    /**
     * Carga una clave pública RSA desde un fichero X509.
     */
    public static PublicKey cargarClavePublica(String ficheroClave) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(ficheroClave)); // Leer el contenido del archivo binario
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA", PROVIDER);
        return kf.generatePublic(spec);
    }

    /**
     * Carga una clave privada RSA desde un fichero PKCS8.
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
