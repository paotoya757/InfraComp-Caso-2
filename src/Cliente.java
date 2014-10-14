import javax.security.auth.x500.X500Principal;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.*;

public class Cliente extends Thread {

	// ------------------------------------------
	// Constantes
	// ------------------------------------------

	public final static String ALGs = "AES";
	public final static String ALGa = "RSA";
	public final static String ALGh = "HMACSHA1";
	public final static String direccion = "infracomp.virtual.uniandes.edu.co";
	public final static int puerto = 80;

	// ------------------------------------------
	// Atributos
	// ------------------------------------------

	private KeyPair parDeLlaves;
	private SecretKey LS;
	private CifradorSimetrico simetrico;
	private CifradorAsimetrico asimetrico;
	private Socket canal;
	private PrintWriter writeStream;
	private BufferedReader readStream;
	private String datos;

	// ------------------------------------------
	// Constructor
	// ------------------------------------------

	public Cliente() {
		try {
			// Generacion de la pareja de llaves (K-,K+)
			KeyPairGenerator gen = KeyPairGenerator.getInstance(ALGa);
			gen.initialize(1024);
			this.parDeLlaves = gen.generateKeyPair();
			// inicializacion del canal
			this.canal = new Socket(direccion, puerto);
			readStream = new BufferedReader(new InputStreamReader(
					canal.getInputStream()));
			writeStream = new PrintWriter(canal.getOutputStream(), true);

		} catch (Exception e) {
			e.printStackTrace();
		}

		// inicializacion de los cifradores
		this.simetrico = new CifradorSimetrico(); // <!> Este debe "setearsele"
													// la llave simetrica cuando
													// se obtenga.
		this.asimetrico = new CifradorAsimetrico(parDeLlaves);

		// inicializacion de los datos de envio. Representacion XML de un Album
		// musical.
		this.datos = "<Album>\n" + "	<TITLE>Empire Burlesque</TITLE>\n"
				+ "	<ARTIST>Bob Dylan</ARTIST>\n" + "	<COUNTRY>USA</COUNTRY>\n"
				+ "	<COMPANY>Columbia</COMPANY>\n" + "	<PRICE>10.90</PRICE>\n"
				+ "	<YEAR>1985</YEAR>\n" + "</Album>";

	}

	// ------------------------------------------
	// Run method
	// ------------------------------------------

	public void run() {

		String in;
		String status;
		String[] temp;
		try {
			writeStream.write("HOLA");
			
			Thread.sleep(5000);
			if (!readStream.ready()) {
				//throw new Exception("NO ESTA LLEGANDO EL MSJ");
			}

			in = readStream.readLine();
			if (!in.equals("ACK"))
				throw new Exception("El servidor no dijo ACKNOWLEDGE");

			writeStream.write("ALGORITMOS" + ":" + ALGs + ":" + ALGa + ":"
					+ ALGh);

			in = readStream.readLine();
			temp = in.split(":");
			status = temp[1];
			if (!temp[0].equals("STATUS")) {
				throw new Exception("El mensaje no tiene el String STATUS ");
			}
			if (status.equals("ERROR"))
				throw new Exception(
						"El servidor no soporta los algoritmos y rompio comunicacion");

			// recibir certificado
			in = readStream.readLine();
			if (!in.equals("CERTSRV"))
				throw new Exception(
						"El servidor no anuncion que viene su certificado");

			InputStream is = canal.getInputStream();
			// no estoy seguro si el input stream esta desde la pos 1 del buffer
			// (osea el 1er msj) o en la ultima que le�.
			// El socket tiene alguna referencia que le de la poscicon de
			// memoria en el buffer de los datos que estan recien entrados ?
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cd_srv = (X509Certificate) cf
					.generateCertificate(is);

			 Key srvPubKey = cd_srv.getPublicKey();// obtencion de la llave publica del servidor

			// enviar certificado
			writeStream.write("CERTCLNT");
			X509Certificate cd_clnt = this.generarCertificadoV3(parDeLlaves);
			canal.getOutputStream().write(cd_clnt.getEncoded());
                        
			// recibir llave secreta
			in = readStream.readLine();
			temp = in.split(":");
			if (!(temp[0]).equals("INIT"))
				throw new Exception(
						"El servidor � yo la embarramos. Entonces fui yo con algo del buffer");

			String LS_encryptada = temp[1];
			// ( descifro la llave secreta ... )

			// re-enviar llave secreta
			byte[] secKey_encrypted = null;
			writeStream.write("INIT"); // + ":" + secKey_encrypted);
			// TODO setearle la llave secreta al Cifrador simetrico object.

			// recibir confirmacion llave secreta
			temp = in.split(":");

			if (!temp[0].equals("STATUS")) {
				throw new Exception("El mensaje no tiene el String STATUS ");
			}
			if (temp[1].equals("ERROR")) {
				throw new Exception(
						"La llave simetrica que le mande al servidor no es la misma que la que el me mando cifrada");
			}

			// enviar datos cifrados con llave simetrica

			writeStream.write("INFO"); // +":"+ cifradoSim_datos);

			// enviar datos con hash para verificar integridad

			// TODO calcular codigo crypto de hash
			// TODO encryptar con llave publica
			writeStream.write("INFO"); // +":"+ cifradoAsimHash_datos );

			// recibir respuesta
			in = readStream.readLine();
			temp = in.split(":");
			if (!temp[0].equals("INFO")) {
				throw new Exception("El mensaje no tiene el String INFO ");
			}

			// rta = Descifrado simetrico(temp[1])

		} catch (Exception e) {
			System.out.println(e.getMessage());
			e.printStackTrace();
		}

		writeStream.close();
		try {
			readStream.close();
			canal.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	// ------------------------------------------
	// Metodos
	// ------------------------------------------

	/**
	 * Crea un certificado X509 Version 3
	 * 
	 * @param pair
	 *            - Pareja de llaves
	 * @return El certificado.
	 * @throws InvalidKeyException
	 * @throws SecurityException
	 * @throws SignatureException
	 */
	@SuppressWarnings("deprecation")
	public X509Certificate generarCertificadoV3(KeyPair pair)
			throws InvalidKeyException, SecurityException, SignatureException {

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X500Principal(
				"CN=Certificado : Cliente InfraComp Caso 2"));
		certGen.setNotBefore(new Date());
		certGen.setNotAfter(new Date(2014, 12, 31));
		certGen.setSubjectDN(new X500Principal(
				"CN=Certificado : Cliente InfraComp Caso 2"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

		return certGen.generateX509Certificate(pair.getPrivate());
	}

	/**
	 * Calcula el codigo HMAC, utilizando el algoritmo "ALGh", correspondiente a
	 * un {} de datos
	 * 
	 * @param datos
	 *            - bytes de los datos a los cuales se les quieren calcular el
	 *            codigo.
	 * @return codigo HMAC en bytes.
	 */
	private byte[] hashCryptoCode(byte[] datos) {
		try {
			String algoritmo = "Hmac" + ALGh.split("HMAC")[1];
			SecretKeySpec key = new SecretKeySpec(this.LS.getEncoded(),
					algoritmo);
			Mac mac = Mac.getInstance(algoritmo);
			mac.init(key);
			byte[] rawHmac = mac.doFinal(datos);
			return rawHmac;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

}
