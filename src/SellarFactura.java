import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SellarFactura {

    /*
    Recibe paquete
    Verifica firma de la empresa con clave pública
    Genera timestamp
    Firma timestamp con clave privada
    Añade timestamp y firma
    Guarda paquete
     */

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            mensajeAyuda();
            System.exit(1);
        }

        String nombrePaquete = args[0];
        String ficheroClavePublicaEmpresa = args[1];
        String ficheroClavePrivadaAutoridad = args[2];

        Security.addProvider(new BouncyCastleProvider());

        // Paso 1: Cargar el paquete
        Paquete paquete = new Paquete(nombrePaquete);

        if (paquete.getContenidoBloque("FIRMA_AUTORIDAD") != null) {
            System.err.println("Error: El paquete ya ha sido sellado.");
            System.exit(1);
        }

        // Paso 2: Verificar la firma de la Empresa
        // Recuperar los bloques necesarios del paquete para verificar la firma de la Empresa
        byte[] facturaCifrada = paquete.getContenidoBloque("FACTURA_CIFRADA");
        byte[] claveCifrada = paquete.getContenidoBloque("CLAVE_CIFRADA");
        byte[] firmaEmpresa = paquete.getContenidoBloque("FIRMA_EMPRESA");

        // Verificar que todos los bloques críticos existen
        if (facturaCifrada == null || claveCifrada == null || firmaEmpresa == null) {
            System.err.println("Error: El paquete no contiene los bloques necesarios.");
            System.exit(1);
        }

        PublicKey clavePublicaEmpresa = cargarClavePublica(ficheroClavePublicaEmpresa); // cargar clave pública de la empresa
        PrivateKey clavePrivadaAutoridad = cargarClavePrivada(ficheroClavePrivadaAutoridad); // cargar clave privada de la autoridad

        // Verificar firma de la Empresa
        byte[] mensajeFirmadoEmpresa = concatenarBytes(facturaCifrada, claveCifrada); // concatenar factura cifrada y clave cifrada
        Signature verificadorEmpresa = Signature.getInstance("SHA512withRSA", "BC");
        verificadorEmpresa.initVerify(clavePublicaEmpresa);
        verificadorEmpresa.update(mensajeFirmadoEmpresa);
        if (!verificadorEmpresa.verify(firmaEmpresa)) {
            System.err.println("La verificación de la firma de la Empresa falló.");
            System.exit(1);
        }

        // Paso 3: Generar Timestamp
        String timestampStr = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        byte[] selloTiempo = timestampStr.getBytes("UTF-8");
        paquete.anadirBloque("SELLO_TIEMPO", selloTiempo);

        // Paso 4: Firmar con la Autoridad
        byte[] mensajeAFirmarAutoridad = concatenarBytes(facturaCifrada, claveCifrada, selloTiempo);
        Signature firmadorAutoridad = Signature.getInstance("SHA512withRSA", "BC");
        firmadorAutoridad.initSign(clavePrivadaAutoridad);
        firmadorAutoridad.update(mensajeAFirmarAutoridad);
        byte[] firmaAutoridad = firmadorAutoridad.sign();
        paquete.anadirBloque("FIRMA_AUTORIDAD", firmaAutoridad);

        // Paso 5: Guardar el paquete sellado
        paquete.escribirPaquete(nombrePaquete);

        System.out.println("ÉXITO: Factura sellada correctamente y guardada en " + nombrePaquete);
    }

    public static void mensajeAyuda() {
        System.out.println("Sella una Factura Empaquetada por la Autoridad de Sellado.");
        System.out.println("\tSintaxis: java SellarFactura <nombre_paquete> <clave_publica_empresa> <clave_privada_autoridad>");
        System.out.println();
    }

    /*
    Carga una clave pública RSA desde un fichero X509.
    Basado en la lógica inversa de GenerarClaves.java.
    */
    public static PublicKey cargarClavePublica(String ficheroClave) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(ficheroClave)); // Leer el contenido del archivo binario
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        return kf.generatePublic(spec);
    }

    /*
    Carga una clave privada RSA desde un fichero PKCS8.
    Basado en la lógica inversa de GenerarClaves.java.
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