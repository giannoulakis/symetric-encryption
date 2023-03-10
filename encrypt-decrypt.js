const readline = require('readline');
const crypto = require('crypto');

const algorithm = 'aes256';
const inputEncoding = 'utf8';
const outputEncoding = 'hex';
const ivlength = 16; // AES blocksize

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const prompt = (query) => new Promise((resolve) => rl.question(query, resolve));

const encrypt = (text, key) => {
	//covert key to md5, because aes-256-cbc requires a 32-byte key
	const md5key = crypto
		.createHash('md5')
		.update(key)
		.digest('hex');
	// iv
	const iv = crypto.randomBytes(ivlength);
	//encrypt using algorithm
	const cipher = crypto.createCipheriv(algorithm, md5key, iv);
	let encrypted = cipher.update(text, inputEncoding, outputEncoding);
	encrypted += cipher.final(outputEncoding);
	//return iv + encrypted
	return iv.toString(outputEncoding) +':'+ encrypted;
};

const decrypt = (ciphertext, key) => {
	//covert key to md5, because aes-256-cbc requires a 32-byte key
    const md5key = crypto.createHash('md5').update(key).digest('hex');

	//split iv and encrypted text
    var components = ciphertext.split(':');
    var iv = Buffer.from(components[0], outputEncoding);
    var encryptedText = Buffer.from(components[1], outputEncoding);
	//decrypt using algorithm
	const decipher = crypto.createDecipheriv(algorithm, md5key, iv);
	let decrypted = decipher.update(encryptedText, outputEncoding, inputEncoding);
    decrypted += decipher.final(inputEncoding);
	return decrypted;
};

//usage inside aync function do not need closure demo only*
(async () => {
	try {
		const action = await prompt('Decrypt (d) or Encrypt (e)? ');
		if (!action.match(/^[de]$/)) {
			throw new Error('Invalid action');
		}
		if (action === 'd') {
			const encryptedText = await prompt('Enter encrypted text: ');
			const key = await prompt('Enter key: ');
			const decrypted = decrypt(encryptedText, key);
			console.log(`Decrypted text: ${decrypted}`);
		} else {
			const text = await prompt('Enter text to encrypt: ');
			const key = await prompt('Enter key: ');
			const encryptedText = encrypt(text, key);
			console.log(`Encrypted text: ${encryptedText}`);
		}
		rl.close();
	} catch (e) {
		console.error('unable to prompt', e);
		rl.close();
	}
})();

//when done reading prompt exit program
rl.on('close', () => process.exit(0));