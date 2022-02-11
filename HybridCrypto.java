import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;


public class HybridCrypto
{
	private static final String INSTANCE_CRYPTO_AES = "AES/GCM/NoPadding";

	private static final int AES_KEY_LENGTH_BIT = 256;

	private static final int IV_LENGTH_BYTE = 16;

	// must be one of {128, 120, 112, 104, 96}
	private static final int TAG_LENGTH_BIT = 128;

	// Utilizar instâncias mais seguras:
	// RSA/None/OAEPWithSHA1AndMGF1Padding ou RSA/NONE/OAEPWithSHA256AndMGF1Padding
	private static final String INSTANCE_CRYPTO_RSA = "RSA/ECB/PKCS1Padding";

	private static final int RSA_KEY_LENGTH_BIT = 2048;

    static SecureRandom srandom = new SecureRandom();

	// Com o parâmetro ci definido, a função criptografa/decriptografa
	// o arquivo in e escreve a saída no arquivo out
    static private void processFile(Cipher ci,InputStream in,OutputStream out)
	throws javax.crypto.IllegalBlockSizeException,
	       javax.crypto.BadPaddingException,
	       java.io.IOException
    {
		byte[] ibuf = new byte[1024];
		int len;
		while ((len = in.read(ibuf)) != -1) {
			byte[] obuf = ci.update(ibuf, 0, len);
			if ( obuf != null ) out.write(obuf);
		}
		byte[] obuf = ci.doFinal();
		if ( obuf != null ) out.write(obuf);
    }

	// Função que gera o par de chaves pública/privada
	// e as adiciona cada uma em um arquivo especifíco
    static private void doGenkey(String[] args)
	throws java.security.NoSuchAlgorithmException,
	       java.io.IOException
    {
		if ( args.length == 0 ) {
			System.err.println("genkey -- need fileBase");
			return;
		}

		int index = 0;
		String fileBase = args[index++];
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(RSA_KEY_LENGTH_BIT);
		KeyPair kp = kpg.generateKeyPair();

		try (FileOutputStream out = new FileOutputStream(fileBase + ".key")) {
			out.write(kp.getPrivate().getEncoded());
		}

		try (FileOutputStream out = new FileOutputStream(fileBase + ".pub")) {
			out.write(kp.getPublic().getEncoded());
		}
    }

	static private void doEncryptRSAWithAES_pvtKey(String[] args)
	throws java.security.NoSuchAlgorithmException,
	       java.security.InvalidAlgorithmParameterException,
	       java.security.InvalidKeyException,
	       java.security.spec.InvalidKeySpecException,
	       javax.crypto.NoSuchPaddingException,
	       javax.crypto.BadPaddingException,
	       javax.crypto.IllegalBlockSizeException,
	       java.io.IOException
    {
		if ( args.length != 2 ) {
			System.err.println("enc_pvt pvtKeyFile inputFile");
			System.exit(1);
		}

		// Lendo o arquivo que contém a chave privada
		int index = 0;
		String pvtKeyFile = args[index++];
		String inputFile = args[index++];
		byte[] bytes = Files.readAllBytes(Paths.get(pvtKeyFile));

		// Configurando a chave privada apropriadamente
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey pvt = kf.generatePrivate(ks);

		// Gera a chave simétrica do AES
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(AES_KEY_LENGTH_BIT, SecureRandom.getInstanceStrong());
		SecretKey skey = kgen.generateKey();

		// Gera o vetor de inicialização
		byte[] iv = new byte[IV_LENGTH_BYTE];
		srandom.nextBytes(iv);

		try (FileOutputStream out = new FileOutputStream(inputFile + ".enc")) {
			{
				// Inicializa a instância de criptografia RSA
				Cipher cipher = Cipher.getInstance(INSTANCE_CRYPTO_RSA);
				cipher.init(Cipher.ENCRYPT_MODE, pvt);

				// Criptografa a chave simétrica do AES
				byte[] b = cipher.doFinal(skey.getEncoded());
				
				// Escreve o resultado no arquivo de saída
				out.write(b);
			}

			// Escreve o vetor de inicialização no arquivo de saída
			out.write(iv);

			// Inicializa a a instância de criptografia AES
			Cipher ci = Cipher.getInstance(INSTANCE_CRYPTO_AES);
			ci.init(Cipher.ENCRYPT_MODE, skey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
			
			// Chamada do procedimento para criptografar os dados 
			// do arquivo de entrada e escrever no arquivo de saída
			try (FileInputStream in = new FileInputStream(inputFile)) {
				processFile(ci, in, out);
			}
		}
    }

	static private void doEncryptRSAWithAES_pubKey(String[] args)
	throws java.security.NoSuchAlgorithmException,
	       java.security.InvalidAlgorithmParameterException,
	       java.security.InvalidKeyException,
	       java.security.spec.InvalidKeySpecException,
	       javax.crypto.NoSuchPaddingException,
	       javax.crypto.BadPaddingException,
	       javax.crypto.IllegalBlockSizeException,
	       java.io.IOException
    {
		if ( args.length != 2 ) {
			System.err.println("enc_pub pubKeyFile inputFile");
			System.exit(1);
		}

		// Lendo o arquivo que contém a chave pública
		int index = 0;
		String pubKeyFile = args[index++];
		String inputFile = args[index++];
		byte[] bytes = Files.readAllBytes(Paths.get(pubKeyFile));

		// Configurando a chave pública apropriadamente
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pub = kf.generatePublic(ks);

		// Gera a chave simétrica do AES
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(AES_KEY_LENGTH_BIT, SecureRandom.getInstanceStrong());
		SecretKey skey = kgen.generateKey();

		// Gera o vetor de inicialização
		byte[] iv = new byte[IV_LENGTH_BYTE];
		srandom.nextBytes(iv);

		try (FileOutputStream out = new FileOutputStream(inputFile + ".enc")) {
			{
				// Inicializa a instância de criptografia RSA
				Cipher cipher = Cipher.getInstance(INSTANCE_CRYPTO_RSA);
				cipher.init(Cipher.ENCRYPT_MODE, pub);

				// Criptografa a chave simétrica do AES
				byte[] b = cipher.doFinal(skey.getEncoded());

				// Escreve o resultado no arquivo de saída
				out.write(b);
			}

			// Escreve o vetor de inicialização no arquivo de saída
			out.write(iv);

			// Inicializa a a instância de criptografia AES
			Cipher ci = Cipher.getInstance(INSTANCE_CRYPTO_AES);
			ci.init(Cipher.ENCRYPT_MODE, skey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
			
			// Chamada do procedimento para criptografar os dados 
			// do arquivo de entrada e escrever no arquivo de saída
			try (FileInputStream in = new FileInputStream(inputFile)) {
				processFile(ci, in, out);
			}
		}
    }


	static private void doDecryptRSAWithAES_pubKey(String[] args)
	throws java.security.NoSuchAlgorithmException,
	       java.security.InvalidAlgorithmParameterException,
	       java.security.InvalidKeyException,
	       java.security.spec.InvalidKeySpecException,
	       javax.crypto.NoSuchPaddingException,
	       javax.crypto.BadPaddingException,
	       javax.crypto.IllegalBlockSizeException,
	       java.io.IOException
    {
		if ( args.length != 2 ) {
			System.err.println("dec_pub pubKeyFile inputFile");
			System.exit(1);
		}

		// Lendo o arquivo que contém a chave pública
		int index = 0;
		String pubKeyFile = args[index++];
		String inputFile = args[index++];
		byte[] bytes = Files.readAllBytes(Paths.get(pubKeyFile));

		// Configurando a chave pública apropriadamente
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pub = kf.generatePublic(ks);

		try (FileInputStream in = new FileInputStream(inputFile)) {
			SecretKeySpec skey = null;
			{
				// Inicializa a instância de decriptografia RSA
				Cipher cipher = Cipher.getInstance(INSTANCE_CRYPTO_RSA);
				cipher.init(Cipher.DECRYPT_MODE, pub);
				
				// Ler os bytes referentes a chave simétrica criptografada
				byte[] b = new byte[256];
				in.read(b);
				
				// Configura a chave simétrica apropriadamente 
				byte[] keyb = cipher.doFinal(b);
				skey = new SecretKeySpec(keyb, "AES");
			}

			// Ler o vetor de inicialização
			byte[] iv = new byte[IV_LENGTH_BYTE];
			in.read(iv);

			// Inicializa a instância de decriptografia AES
			Cipher ci = Cipher.getInstance(INSTANCE_CRYPTO_AES);
			ci.init(Cipher.DECRYPT_MODE, skey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

			// Chamada do procedimento para decriptografar os dados restantes 
			// do arquivo de entrada e escrever no arquivo de saída
			try (FileOutputStream out = new FileOutputStream(inputFile+".ver")){
				processFile(ci, in, out);
			}
		}
    }

	static private void doDecryptRSAWithAES_pvtKey(String[] args)
	throws java.security.NoSuchAlgorithmException,
	       java.security.InvalidAlgorithmParameterException,
	       java.security.InvalidKeyException,
	       java.security.spec.InvalidKeySpecException,
	       javax.crypto.NoSuchPaddingException,
	       javax.crypto.BadPaddingException,
	       javax.crypto.IllegalBlockSizeException,
	       java.io.IOException
    {
		if ( args.length != 2 ) {
			System.err.println("dec_pvt pvtKeyFile inputFile");
			System.exit(1);
		}

		// Lendo o arquivo que contém a chave privada
		int index = 0;
		String pvtKeyFile = args[index++];
		String inputFile = args[index++];
		byte[] bytes = Files.readAllBytes(Paths.get(pvtKeyFile));

		// Configurando a chave privada apropriadamente
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey pvt = kf.generatePrivate(ks);
	

		try (FileInputStream in = new FileInputStream(inputFile)) {
			SecretKeySpec skey = null;
			{
				// Inicializa a instância de decriptografia RSA
				Cipher cipher = Cipher.getInstance(INSTANCE_CRYPTO_RSA);
				cipher.init(Cipher.DECRYPT_MODE, pvt);

				// Ler os bytes referentes a chave simétrica criptografada
				byte[] b = new byte[256];
				in.read(b);

				// Configura a chave simétrica apropriadamente
				byte[] keyb = cipher.doFinal(b);
				skey = new SecretKeySpec(keyb, "AES");
			}

			// Ler o vetor de inicialização
			byte[] iv = new byte[IV_LENGTH_BYTE];
			in.read(iv);

			// Inicializa a instância de decriptografia AES
			Cipher ci = Cipher.getInstance(INSTANCE_CRYPTO_AES);
			ci.init(Cipher.DECRYPT_MODE, skey, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

			// Chamada do procedimento para decriptografar os dados restantes 
			// do arquivo de entrada e escrever no arquivo de saída
			try (FileOutputStream out = new FileOutputStream(inputFile+".ver")){
				processFile(ci, in, out);
			}
		}
    }

    static public void main(String[] args) throws Exception
    {
	if ( args.length == 0 ) {
	    System.err.print("usage: java sample1 command params..\n" +
			     "where commands are:\n" +
			     "  genkey fileBase\n" +
			     "  enc_pub pubKeyFile inputFile\n" +
				 "  enc_pvt pvtKeyFile inputFile\n" +
			     "  dec_pub pubKeyFile inputFile\n" +
			     "  dec_pvt pvtKeyFile inputFile\n");
	    System.exit(1);
	}

	int index = 0;
	String command = args[index++];
	String[] params = Arrays.copyOfRange(args, index, args.length);
	if ( command.equals("genkey") ) {
		doGenkey(params);
		System.out.println("Par de chaves publico/privado criado");
	}

	else if ( command.equals("enc_pub") ) {
		doEncryptRSAWithAES_pubKey(params);

		System.out.println("Arquivo criptografado");
	}

	else if ( command.equals("enc_pvt") ) {
		doEncryptRSAWithAES_pvtKey(params);

		System.out.println("Arquivo criptografado");
	}

	else if ( command.equals("dec_pvt") ) {
		doDecryptRSAWithAES_pvtKey(params);
		
		System.out.println("Arquivo decriptografado");
	}

	else if ( command.equals("dec_pub") ) {
		doDecryptRSAWithAES_pubKey(params);
		
		System.out.println("Arquivo decriptografado");
	}

	else throw new Exception("Unknown command: " + command);
    }
}
