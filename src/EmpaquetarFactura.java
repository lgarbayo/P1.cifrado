import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;

public class EmpaquetarFactura {

    /*
    Lee factura en formato JSON
    Genera clave simétrica AES-256
    Cifra contendio de factura con AES
    Cifra clave AES con RSA (clave pública de Hacienda)
    Firma paquete con clave privada de la empresa
    Genera paquete con:
        - bloque con factura cifrada
        - bloque con clave AES cifrada
        - bloque con firma del paquete
    Guarda paquete en fichero
     */
    
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            mensajeAyuda();
            System.exit(1);
        }

        Path factura = Paths.get(args[0]);
        Path paquete = Paths.get(args[1]);
        Path haciendaPublicKey = Paths.get(args[2]);
        Path empresaPrivateKey = Paths.get(args[3]);

        // Paso 1: Leer la factura JSON original
        byte[] facturaBytes = Files.readAllBytes(factura);

        // Paso 2: Generar clave simétrica AES y vector de inicialización (IV)
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // por compatibilidad con cualquier instalación de Java, 128 / 16 -> 16 bytes
        SecretKey aesKey = keyGen.generateKey(); // genera clave binaria de 16 bytes que se usará en el cifrado AES
        byte[] iv = new byte[16]; // iv -> vector de inicialización
        SecureRandom random = new SecureRandom(); // genera 16 bytes aleatorios
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv); // etiqueta de autenticación de 16 bytes (128 bits)

        // Paso 3: Cifrar contenido de la factura con clave AES
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] facturaCifrada = aesCipher.doFinal(facturaBytes);
        // doFinal procesa cualquier bloque pendiente, aplica el padding, ejecuta el cifrado y devuelve el texto cifrado en bytes resultantes

        // Paso 4: Preparar la clave pública de Hacienda y cifrar la clave AES
        byte[] haciendaPubBytes = Files.readAllBytes(haciendaPublicKey); // cargamos la clave pública de Hacienda leyendo sus bytes
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(haciendaPubBytes); // convertimos los bytes en una clave pública X.509
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey haciendaPubKey = keyFactory.generatePublic(pubSpec); // generamos la clave pública de Hacienda
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, haciendaPubKey); // inicializamos el cifrado con la clave pública de Hacienda
        byte[] aesEncryptedKey = rsaCipher.doFinal(aesKey.getEncoded()); // cifrar la clave AES con OAEP (Optimal Asymmetric Encryption Padding)

        // Paso 5: Firmar paquete con la clave privada de la Empresa
        byte[] empresaPrivBytes = Files.readAllBytes(empresaPrivateKey); // cargamos la clave privada de la Empresa leyendo sus bytes
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(empresaPrivBytes); // convertimos los bytes en una clave privada PKCS#8
        PrivateKey empresaPrivKey = keyFactory.generatePrivate(privSpec); // generamos la clave privada de la Empresa
        Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(empresaPrivKey); // inicializamos el firmador con la clave privada de la Empresa 
        signature.update(facturaCifrada); // actualizamos el firmador con el contenido crítico
        signature.update(aesEncryptedKey); // actualizamos el firmador con la clave cifrada
        byte[] firmaEmpresa = signature.sign(); // firmamos el contenido crítico

        // Paso 6: Construir el paquete con todos los bloques necesarios
        Paquete paqueteFactura = new Paquete();
        paqueteFactura.anadirBloque("FACTURA_CIFRADA", facturaCifrada);
        paqueteFactura.anadirBloque("CLAVE_CIFRADA", aesEncryptedKey);
        paqueteFactura.anadirBloque("VECTOR_INICIALIZACION", iv);
        paqueteFactura.anadirBloque("FIRMA_EMPRESA", firmaEmpresa);

        // Paso 7: Guardar el paquete en disco
        paqueteFactura.escribirPaquete(paquete.toString());

        System.out.println("Factura empaquetada correctamente en " + paquete);
    }

    private static void mensajeAyuda() {
        System.out.println("Uso: EmpaquetarFactura <fichero JSON factura> <nombre paquete> <clave pública Hacienda> <clave privada Empresa>");
        System.out.println("\tSintaxis:   java EmpaquetarFactura factura.json paquete.zip hacienda.publica empresa.privada");
        System.out.println();
    }
}