import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;

/**
 *
 * @author ribadas
 */
public class Paquete {

    private Map<String, Bloque> bloques;

    public Paquete() {
        this.bloques = new HashMap<>();
    }

    public Paquete(String nombreFichero) {
        this();
        this.leerPaquete(nombreFichero);
    }

    public byte[] getContenidoBloque(String nombreBloque) {
        String nombreNormalizado = normalizarNombre(nombreBloque);
        Bloque bloque = this.bloques.get(nombreNormalizado);
        if (bloque != null) {
            return bloque.contenido;
        } else {
            return null;
        }
    }

    public void anadirBloque(String nombre, byte[] contenido) {
        if (this.bloques == null) {
            this.bloques = new HashMap<>();
        }
        String nombreNormalizado = normalizarNombre(nombre);
        this.bloques.put(nombreNormalizado, new Bloque(nombreNormalizado, contenido));
    }

    public void actualizarBloque(String nombre, byte[] contenido) {
        if (this.bloques != null) {
            if (this.bloques.containsKey(nombre)) {
                Bloque bloque = new Bloque(nombre, contenido);
                this.bloques.replace(nombre, bloque);
            } else {
                this.anadirBloque(nombre, contenido);
            }
        }
    }

    public void eliminarBloque(String nombre) {
        if (this.bloques != null) {
            this.bloques.remove(nombre);
        }
    }

    public List<String> getNombresBloque() {
        List<String> result = new ArrayList<>(this.bloques.keySet());

        Collections.sort(result);
        return result;
    }

    private String normalizarNombre(String nombreBloque) {
        String result = nombreBloque.trim().replaceAll(" ", "_").toUpperCase();
        return result;
    }

    public final static String MARCA_CABECERA = "-----";
    public final static String INICIO_PAQUETE = MARCA_CABECERA + "INICIO PAQUETE" + MARCA_CABECERA;
    public final static String FIN_PAQUETE = MARCA_CABECERA + "FIN PAQUETE" + MARCA_CABECERA;
    public final static String INICIO_BLOQUE = MARCA_CABECERA + "INICIO BLOQUE";
    public final static String FIN_BLOQUE = MARCA_CABECERA + "FIN BLOQUE";
    public final static String INICIO_BLOQUE_FORMATO = INICIO_BLOQUE + " %s" + MARCA_CABECERA;
    public final static String FIN_BLOQUE_FORMATO = FIN_BLOQUE + " %s" + MARCA_CABECERA;
    public final static int ANCHO_LINEA = 65;

    public void leerPaquete(String nombreFichero) {
        try (InputStream in = new FileInputStream(nombreFichero)) {
            this.leerPaquete(in);
        } catch (FileNotFoundException ex) {
            System.err.println("No existe fichero de paquete " + nombreFichero);
            ex.printStackTrace(System.err);
            System.exit(1);
        } catch (IOException ex) {
            System.err.println("Error en fichero de paquete " + nombreFichero);
            ex.printStackTrace(System.err);
            System.exit(1);
        }
    }

    public void escribirPaquete(String nombreFichero) {
        try (PrintStream out = new PrintStream(nombreFichero)) {
            this.escribirPaquete(out);
        } catch (FileNotFoundException ex) {
            System.err.println("Error escribiendo fichero de paquete " + nombreFichero);
            ex.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private void leerPaquete(InputStream entrada) throws IOException {
        BufferedReader in = new BufferedReader(new InputStreamReader(entrada));
        String linea = in.readLine();

        while (!linea.equals(INICIO_PAQUETE)) {
            linea = in.readLine();
        }
        Paquete.Bloque bloque = leerBloque(in);
        while (bloque != null) {
            this.anadirBloque(bloque.nombre, bloque.contenido);
            bloque = leerBloque(in);
        }
    }

    private void escribirPaquete(PrintStream out) {
        out.println(INICIO_PAQUETE);
        for (String nombreBloque : this.getNombresBloque()) {
            escribirBloque(out, nombreBloque, this.getContenidoBloque(nombreBloque));
        }
        out.println(FIN_PAQUETE);
    }

    private void escribirBloque(PrintStream out, String nombreBloque, byte[] contenido) {
        if ((nombreBloque != null) && (contenido != null)) {
            out.printf(INICIO_BLOQUE_FORMATO + "\n", nombreBloque);

            byte[] contenidoBASE64 = Base64.getEncoder().encode(contenido);

            int lineas = contenidoBASE64.length / ANCHO_LINEA;
            int resto = contenidoBASE64.length % ANCHO_LINEA;
            for (int i = 0; i < lineas; i++) {
                out.println(new String(contenidoBASE64, i * ANCHO_LINEA, ANCHO_LINEA));
            }
            out.println(new String(contenidoBASE64, lineas * ANCHO_LINEA, resto));

            out.printf(FIN_BLOQUE_FORMATO + "\n", nombreBloque);
        }
    }

    private Paquete.Bloque leerBloque(BufferedReader in) throws IOException {
        String linea = in.readLine();
        while ((!linea.startsWith(INICIO_BLOQUE) && (!linea.equals(FIN_PAQUETE)))) {
            linea = in.readLine();
        }
        if (linea.equals(FIN_PAQUETE)) {
            return null;  // No hay mÃ¡s bloques
        } else {
            String nombre = extraerNombreBloque(linea);
            byte[] contenido = extraerContenidoBloque(in);
            return new Paquete.Bloque(nombre, contenido);
        }
    }

    private String extraerNombreBloque(String texto) {
        int inicioNombreBloque = INICIO_BLOQUE.length() + 1;
        int finNombreBloque = texto.lastIndexOf(MARCA_CABECERA);
        return texto.substring(inicioNombreBloque, finNombreBloque);
    }

    private byte[] extraerContenidoBloque(BufferedReader in) throws IOException {
        List<String> partesBloque = new ArrayList<>();
        int tamanoBloque = 0;

        String linea = in.readLine(); // Avanzar una linea
        while (!linea.startsWith(FIN_BLOQUE)) {
            partesBloque.add(linea);
            tamanoBloque += linea.length();
            linea = in.readLine();
        }

        byte[] result = new byte[tamanoBloque];
        int posicion = 0;
        for (String parte : partesBloque) {
            byte[] contenidoParte = parte.getBytes();
            for (byte b : contenidoParte) {
                result[posicion] = b;
                posicion++;
            }
        }
        return Base64.getDecoder().decode(result);
    }

    public static class Bloque {

        public String nombre;
        public byte[] contenido;

        public Bloque(String nombre, byte[] contenido) {
            this.nombre = nombre;
            this.contenido = contenido;
        }

    }

    /*
     * Ejemplo de uso de la clase Paquete
     */
    public static void main(String[] args) {

        System.out.println("** Se crea un paquete y se escribe en /tmp/paquete1.bin");

        // Crea un Paquete vacio y le aÃ±ade 3 bloques
        Paquete paquete = new Paquete();
        byte[] datosParte1 = "abcdefg".getBytes(Charset.forName("UTF-8"));
        paquete.anadirBloque("parte1", datosParte1);
        byte[] datosParte2 = "abc".getBytes(Charset.forName("UTF-8"));
        paquete.anadirBloque("parte2", datosParte2);
        byte[] datosParte3 = "abcdefghijklmnÃ±opqrstuvwxyz1234567890".getBytes(Charset.forName("UTF-8"));
        paquete.anadirBloque("parte3 muy larga", datosParte3);

        // Escribe el Paquete al fichero indicado
        paquete.escribirPaquete("/tmp/paquete1.bin");

        System.out.println("");


        System.out.println("** Se lee el paquete de /tmp/paquete1.bin y se vuelve a escribir en /tmp/paquete2.bin");
        // Crea un Paquete leyendo su contenido del fichero indicado
        Paquete paqueteLeido = new Paquete("/tmp/paquete1.bin");
        paqueteLeido.escribirPaquete("/tmp/paquete2.bin");

        System.out.println();

        System.out.println("** Bloques del paquete leido (convertidos a String)");
        for (String nombreBloque : paqueteLeido.getNombresBloque()) {
            byte[] bloque = paqueteLeido.getContenidoBloque(nombreBloque);
            String contenidoBloque = new String(bloque, Charset.forName("UTF-8"));
            System.out.println("\t" + nombreBloque + ": " + contenidoBloque.replace("\n", " "));
        }


    }
}