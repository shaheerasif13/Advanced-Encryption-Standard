import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class Main {

	// Method to read plain texts from file
	public static ArrayList<String> readPlainTextFromFile(String fileName) {

		if (fileName.contains(".pt")) {

			try {
				BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));
				ArrayList<String> plainTexts = new ArrayList<String>();
				String line = bufferedReader.readLine();

				while (line != null) {

					// Padding plain text with 0's if length is less than 32 hex characters
					while (line.length() < 32) {
						line += "0";
					}

					plainTexts.add(line);
					line = bufferedReader.readLine();
				}

				bufferedReader.close();
				return plainTexts;
			}

			catch (IOException e) {
				return null;
			}
		}

		return null;
	}

	// Method to read key from file
	public static String readKeyFromFile(String fileName) {

		if (fileName.contains(".key")) {

			try {
				BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));
				String line = bufferedReader.readLine();
				bufferedReader.close();
				return line;
			}

			catch (IOException e) {
				return null;
			}
		}

		return null;
	}

	// Method to write encrypted/decrypted to file
	public static void writeTextToFile(ArrayList<String> texts, String fileName) {

		try {
			BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(fileName));

			for (int i = 0; i < texts.size(); i++) {
				bufferedWriter.write(texts.get(i).toUpperCase());

				if (i != texts.size() - 1) {
					bufferedWriter.write("\n");
				}
			}

			bufferedWriter.close();
		}

		catch (IOException e) {
			e.printStackTrace();
		}

	}

	// Method to run AES encryption and decryption
	public static void runAES(ArrayList<String> plainTexts, String key, String mode) throws Exception {

		// Making two different instances for encryption and decryption because in CBC
		// mode AES maintains state so another instance is required for decryption
		AdvancedEncryptionStandard AESForEncryption = null;
		AdvancedEncryptionStandard AESForDecryption = null;

		if (mode.equalsIgnoreCase("ecb")) { // If ECB mode is selected

			// Initializing AESECB instances
			AESForEncryption = new AdvancedEncryptionStandardECB(key);
			AESForDecryption = new AdvancedEncryptionStandardECB(key);
		}

		else if (mode.equalsIgnoreCase("cbc")) { // If CBC mode is selected

			// Generating initialization vector
			String initializationVector = "";

			for (int i = 0; i < 32; i++) {
				initializationVector += Integer.toHexString((int) (Math.random() * 16));
			}

			System.out.println("\nInitialization vector: " + initializationVector.toUpperCase());

			// Initializing AESCBC instances
			AESForEncryption = new AdvancedEncryptionStandardCBC(key, initializationVector);
			AESForDecryption = new AdvancedEncryptionStandardCBC(key, initializationVector);
		}

		// Displaying cipher key
		System.out.println("\nThe cipher key is:");
		AESForEncryption.displayMatrix(AESForEncryption.convertStringToMatrix(key, true), false);

		// Displaying expanded keys
		System.out.println("\nThe expanded key is:");
		AESForEncryption.displayExpandedKeys();

		// Starting encryption of plain texts
//		System.out.println("\nThe Encryption:");
		ArrayList<String> encryptedTexts = new ArrayList<String>();
		long startTime = System.nanoTime();

		for (String plainText : plainTexts) {

//			System.out.println("\nThe plaintext is:");
//			AESForEncryption.displayMatrix(AESForEncryption.convertStringToMatrix(plainText, false), false);

			String encryptedText = AESForEncryption.encrypt(plainText);
			encryptedTexts.add(encryptedText);

//			System.out.println("\nThe encryption of plaintext is:");
//			AESForEncryption.displayMatrix(AESForEncryption.convertStringToMatrix(encryptedText, false), false);
		}

		long endTime = System.nanoTime();

		// Calculating throughput time for encryption
		long encryptionExecutionTime = endTime - startTime;
		int plainTextLength = plainTexts.size() * 32;
		double encryptionThroughputTime = (((double) plainTextLength / encryptionExecutionTime) / 2) / (1024 * 1024);

		// Starting decryption of cipher texts
//		System.out.println("\nThe Decryption:");
		ArrayList<String> decryptedTexts = new ArrayList<String>();
		startTime = System.nanoTime();

		for (String encryptedText : encryptedTexts) {

//			System.out.println("\nThe ciphertext is:");
//			AESForDecryption.displayMatrix(AESForDecryption.convertStringToMatrix(encryptedText, false), false);

			String decryptedText = AESForDecryption.decrypt(encryptedText);
			decryptedTexts.add(decryptedText);

//			System.out.println("\nThe decryption of ciphertext is:");
//			AESForDecryption.displayMatrix(AESForDecryption.convertStringToMatrix(decryptedText, false), false);
		}

		endTime = System.nanoTime();

		// Calculating throughput time for decryption
		long decryptionExecutionTime = endTime - startTime;
		double decryptionThroughputTime = (((double) plainTextLength / decryptionExecutionTime) / 2) / (1024 * 1024);

		// Writing encrypted/decrypted texts to files
		Main.writeTextToFile(encryptedTexts, "encrypted.enc");
		Main.writeTextToFile(decryptedTexts, "decrypted.dec");

		// Displaying formatted plain, encrypted, and decrypted texts
		System.out.println(String.format("\n%-32s\t%-32s\t%-32s", "Plain Text", "Encrypted Text", "Decrypted Text"));
		for (int i = 0; i < plainTexts.size(); i++) {
			System.out.println(plainTexts.get(i) + "\t" + encryptedTexts.get(i).toUpperCase() + "\t"
					+ decryptedTexts.get(i).toUpperCase());
		}

		// Displaying time for encryption/decryption
		System.out.println("\nEncryption execution time: " + encryptionExecutionTime);
		System.out.println("Encryption throughput: " + encryptionThroughputTime);
		System.out.println("Decryption execution time: " + decryptionExecutionTime);
		System.out.println("Decryption throughput: " + decryptionThroughputTime);
	}

	public static void main(String[] args) throws Exception {

		if (args.length != 3) {
			System.err.println("Missing arguments!");
			System.err.println("Usage: java Main <plaintextfile> <keyfile> <mode>");
		}

		else {
			ArrayList<String> plainTexts = Main.readPlainTextFromFile(args[0]);
			String key = Main.readKeyFromFile(args[1]);
			String mode = args[2];
			boolean isInputValid = true;

			if (plainTexts == null || plainTexts.size() == 0) {
				isInputValid = false;
				System.err.println(
						"Plain texts not found. Make sure file exists, is not empty, and has extension \".pt\"!");
			}

			if (key == null || key.length() == 0) {
				isInputValid = false;
				System.err.println("Key not found. Make sure file exists, is not empty, and has extension \".key\"!");
			}

			else if (key.length() != 32 && key.length() != 48 && key.length() != 64) {
				isInputValid = false;
				System.err.println("Invalid key length. Valid key lengths are 128, 192, and 256!");
			}

			if (!mode.equalsIgnoreCase("ecb") && !mode.equalsIgnoreCase("cbc")) {
				isInputValid = false;
				System.err.println("Invalid mode selected. Valid modes are ECB and CBC!");
			}

			if (isInputValid) {
				Main.runAES(plainTexts, key, mode);
			}
		}
	}
}