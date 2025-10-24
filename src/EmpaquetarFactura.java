import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.zip.*;
import java.util.Base64;

public class EmpaquetarFactura {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println("Uso: EmpaquetarFactura <fichero JSON factura> <nombre paquete> <clave pública Hacienda>");
            System.exit(1);
        }

        Path factura = Paths.get(args[0]);
        Path paquete = Paths.get(args[1]);
        Path haciendaPublicKey = Paths.get(args[2]);
        Path empresaPrivateKey = Paths.get(args[3]);

        // Paso 1: Leer factura JSON
        byte[] facturaBytes = Files.readAllBytes(factura);

        // Paso 2: Generar clave simétrica AES
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        // inicializar generador de clave AES
        keyGen.init(128); // por compatibilidad con cualquier instalación de Java, 128 / 16 -> 16 bytes
        SecretKey aesKey = keyGen.generateKey(); // genera clave binaria de 16 bytes que se usará en el cifrado AES
        byte[] iv = new byte[16];
        SecureRandom random = new SecureRandom(); // genera 16 bytes aleatorios
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // Paso 3: Cifrar factura con aesKey
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
        byte[] facturaCifrada = aesCipher.doFinal(facturaBytes);

        // Paso 4: Cifrar clave AES con RSA (public key de Hacienda)

    }
}