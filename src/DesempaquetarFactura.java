import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarFactura {

    /*
    Verifica firma de la Autoridad
    Obtiene sellado
    Verifica firma de la Empresa
    Descifra clave AES con clave privada de Hacienda
    Descifra factura con clave AES
    Guarda factura en claro y muestra resultado
     */

     public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            mensajeAyuda();
            System.exit(1);
        }

        String nombrePaquete = args[0];
        String facturaJson = args[1];
        String ficheroClavePrivadaHacienda = args[2];
        String ficheroClavePublicaEmpresa = args[3];
        String ficheroClavePublicaAutoridad = args[4];

        Security.addProvider(new BouncyCastleProvider());

        // Cargar el paquete sellado desde disco
        Paquete paquete = new Paquete(nombrePaquete);

        // Recuperar todos los bloques necesarios del paquete
        byte[] facturaCifrada = paquete.getContenidoBloque("FACTURA_CIFRADA");
        byte[] claveCifrada = paquete.getContenidoBloque("CLAVE_CIFRADA");
        byte[] firmaEmpresa = paquete.getContenidoBloque("FIRMA_EMPRESA");
        byte[] selloTiempo = paquete.getContenidoBloque("SELLO_TIEMPO");
        byte[] firmaAutoridad = paquete.getContenidoBloque("FIRMA_AUTORIDAD");
        byte[] iv = paquete.getContenidoBloque("VECTOR_INICIALIZACION");

        // Verificar que todos los bloques críticos existen
        if (facturaCifrada == null || claveCifrada == null || firmaEmpresa == null || selloTiempo == null || firmaAutoridad == null) {
            System.err.println("¡ERROR CRÍTICO! El paquete está incompleto. Faltan bloques de Empresa y/o Autoridad.");
            System.exit(1);
        }
        if (iv == null) {
            System.err.println("¡ERROR CRÍTICO! Falta el vector de inicialización (VECTOR_INICIALIZACION) en el paquete.");
            System.exit(1);
        }

        // Cargar las claves criptográficas necesarias
        PublicKey clavePublicaEmpresa = cargarClavePublica(ficheroClavePublicaEmpresa); // para verificar firma de la Empresa
        PublicKey clavePublicaAutoridad = cargarClavePublica(ficheroClavePublicaAutoridad); // para verificar firma de la Autoridad
        PrivateKey clavePrivadaHacienda = cargarClavePrivada(ficheroClavePrivadaHacienda); // para descifrar la clave AES

        // Paso 1: Verificar la firma de la Autoridad de Sellado (integridad del sello de tiempo)
        byte[] mensajeAFirmarAutoridad = concatenarBytes(facturaCifrada, claveCifrada, selloTiempo); // concatenar todos los datos que la Autoridad firmó
        Signature verificadorAutoridad = Signature.getInstance("SHA512withRSA", "BC"); // inicializar verificador con SHA-512 y RSA
        verificadorAutoridad.initVerify(clavePublicaAutoridad); // inicializar la verificación con la clave pública de la Autoridad
        verificadorAutoridad.update(mensajeAFirmarAutoridad); // actualizar el verificador con el mensaje original
        if (!verificadorAutoridad.verify(firmaAutoridad)) {
            System.err.println("Firma de la Autoridad: ¡FALLIDA! El Sello de Tiempo o los datos originales fueron alterados.");
            System.exit(1);
        }

        // Paso 2: Obtener el sello de tiempo
        String timestampStr = new String(selloTiempo, "UTF-8"); // convertir el timestamp de bytes a String
        System.out.println("Sello de Tiempo (Timestamp): " + timestampStr);

        // Paso 3: Verificar la firma de la Empresa
        byte[] mensajeFirmadoEmpresa = concatenarBytes(facturaCifrada, claveCifrada); // concatenar los datos que la Empresa firmó originalmente
        Signature verificadorEmpresa = Signature.getInstance("SHA512withRSA", "BC"); // inicializar verificador con SHA-512 y RSA
        verificadorEmpresa.initVerify(clavePublicaEmpresa); // inicializar la verificación con la clave pública de la Empresa
        verificadorEmpresa.update(mensajeFirmadoEmpresa); // actualizar el verificador con el mensaje original
        if (!verificadorEmpresa.verify(firmaEmpresa)) {
            System.err.println("Firma de la Empresa: ¡FALLIDA! El contenido de la Empresa fue alterado o la clave pública es incorrecta.");
            System.exit(1);
        }

        // Paso 4: Descifrar la clave simétrica AES con la clave privada de Hacienda usando RSA/OAEP
        Cipher descifradorRSA = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "BC"); // inicializar descifrador RSA con OAEP
        descifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivadaHacienda); // modo descifrado con la clave privada de Hacienda
        byte[] claveAESDescifrada = descifradorRSA.doFinal(claveCifrada); // descifrar la clave AES
        SecretKey claveSimetrica = new SecretKeySpec(claveAESDescifrada, "AES"); // construir objeto SecretKey a partir de los bytes descifrados

        // Paso 5: Descifrar la factura con la clave simétrica AES usando modo CBC y el IV guardado
        Cipher descifradorAES = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC"); // inicializar descifrador AES en modo CBC
        IvParameterSpec ivSpec = new IvParameterSpec(iv); // crear especificación del IV
        descifradorAES.init(Cipher.DECRYPT_MODE, claveSimetrica, ivSpec); // modo descifrado con la clave simétrica y el IV
        byte[] facturaDescifrada = descifradorAES.doFinal(facturaCifrada); // descifrar la factura y quitar el padding
        String facturaClaro = new String(facturaDescifrada, "UTF-8"); // convertir los bytes descifrados a String UTF-8

        // Paso 6: Guardar la factura descifrada en el archivo de salida
        Files.write(Paths.get(facturaJson), facturaClaro.getBytes("UTF-8"));

        System.out.println("Descifrado completo. Factura original guardada en: " + facturaJson);
    }

    public static void mensajeAyuda() {
        System.out.println("Desempaqueta y verifica una Factura Sellada en Hacienda.");
        System.out.println("\tSintaxis: java DesempaquetarFactura <paquete_sellado> <fichero_json_salida> <clave_privada_hacienda> <clave_publica_empresa> <clave_publica_autoridad>");
        System.out.println();
    }

    /*
    Carga una clave pública RSA desde un fichero X509.
    */
    public static PublicKey cargarClavePublica(String ficheroClave) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(ficheroClave)); // Leer el contenido del archivo binario
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        return kf.generatePublic(spec);
    }

    /*
    Carga una clave privada RSA desde un fichero PKCS8.
    */
    public static PrivateKey cargarClavePrivada(String ficheroClave) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(ficheroClave)); // Leer el contenido del archivo binario
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        return kf.generatePrivate(spec);
    }

    /*
    Concatena arrays de bytes para generar el mensaje a firmar/verificar.
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