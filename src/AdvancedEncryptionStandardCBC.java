public class AdvancedEncryptionStandardCBC extends AdvancedEncryptionStandard {

	private String lastCipherBlock;

	public AdvancedEncryptionStandardCBC(String key, String initializationVector) {
		super(key);
		this.lastCipherBlock = initializationVector;
	}

	@Override
	public String encrypt(String plainText) {

		// Setting plain text as plain text hex matrix
		String[][] plainTextMatrix = this.convertStringToMatrix(plainText, false);

		// Setting last cipher block as hex matrix
		String[][] lastCipherBlockMatrix = this.convertStringToMatrix(this.lastCipherBlock, false);

		// Matrix for storing result of XOR between plain text and last cipher block
		String[][] preCipherTextMatrix = new String[this.Nb][this.Nb];

		// Taking XOR of plain text with last cipher block
		for (int i = 0; i < this.Nb; i++) {

			for (int j = 0; j < this.Nb; j++) {
				preCipherTextMatrix[i][j] = Integer.toHexString(Integer.parseInt(plainTextMatrix[i][j], 16)
						^ Integer.parseInt(lastCipherBlockMatrix[i][j], 16));

				// If length of hex number id 1 append zero at start
				if (preCipherTextMatrix[i][j].length() == 1) {
					preCipherTextMatrix[i][j] = "0" + preCipherTextMatrix[i][j];
				}
			}
		}

		// Converting plain text hex matrix back to plain text string
		String preCipherText = this.convertMatrixToString(preCipherTextMatrix);

		// Setting last cipher block as current encrypted cipher text
		this.lastCipherBlock = super.encrypt(preCipherText);

		return this.lastCipherBlock;
	}

	@Override
	public String decrypt(String cipherText) {

		// Setting cipher text as cipher text hex matrix
		String[][] cipherTextMatrix = this.convertStringToMatrix(super.decrypt(cipherText), false);

		// Setting last cipher block as hex matrix
		String[][] lastCipherBlockMatrix = this.convertStringToMatrix(this.lastCipherBlock, false);

		// Matrix for storing result of XOR between decrypted cipher text and last
		// cipher block
		String[][] plainTextMatrix = new String[this.Nb][this.Nb];

		// Taking XOR of cipher text with last cipher block
		for (int i = 0; i < cipherTextMatrix.length; i++) {

			for (int j = 0; j < cipherTextMatrix[0].length; j++) {
				plainTextMatrix[i][j] = Integer.toHexString(Integer.parseInt(cipherTextMatrix[i][j], 16)
						^ Integer.parseInt(lastCipherBlockMatrix[i][j], 16));

				// If length of hex number id 1 append zero at start
				if (plainTextMatrix[i][j].length() == 1) {
					plainTextMatrix[i][j] = "0" + plainTextMatrix[i][j];
				}
			}
		}

		// Setting last cipher block as current encrypted cipher text
		this.lastCipherBlock = cipherText;

		// Converting cipher text hex matrix back to cipher text string
		String plainText = this.convertMatrixToString(plainTextMatrix);

		return plainText;
	}
}