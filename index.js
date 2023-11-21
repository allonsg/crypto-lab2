const gost89 = require("gost89");
const crypto = require('crypto');
const readline = require('readline');

const gost = gost89.init();

// const iv = crypto.randomBytes(8);
const algorithm = 'aes-256-ofb';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

const padMessage = (message) => {
    const padding = '0'.repeat(8 - (message.length % 8));
    return message + padding;
}

const removePadding = (message) => {
    return message.replace(/0+$/, '');
}

const encryptInECB = (message) => {
    const paddedMessage = padMessage(message);

    const clear = Buffer.from(paddedMessage, 'binary');
    const out = gost.crypt(clear);
    return out.toString('base64');
}

const decryptInECB = (messageInBase64) => {
    const clear = Buffer.from(messageInBase64, 'base64');
    const out = gost.decrypt(clear);
    const outHex = out.toString('binary');
    const unpaddedMessage = removePadding(outHex);
    return unpaddedMessage
}

const encryptInOFB = (message) => {
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

const decryptInOFB = (messageInHex) => {
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(messageInHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

const encryptInCFB = (message) => {
    const clear = Buffer.from(message, 'binary');
    const out = gost.crypt_cfb(iv, clear);
    const outHex = out.toString('hex');
    return outHex
}

const decryptInCFB = (messageInHex) => {
    const clear = Buffer.from(messageInHex, 'hex');
    const out = gost.decrypt_cfb(iv, clear);
    const outHex = out.toString('binary');
    return outHex
}

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question('What type of encryption do you want to use? (ECB/CFB/OFB) ', (encryptionType) => {
    rl.question('Enter a message to encrypt: ', (message) => {
        let encryptedMessage;
        let decryptedMessage;

        if (encryptionType.toLowerCase() === 'ecb') {
            encryptedMessage = encryptInECB(message);
            decryptedMessage = decryptInECB(encryptedMessage);
        } else if (encryptionType.toLowerCase() === 'cfb') {
            encryptedMessage = encryptInCFB(message);
            decryptedMessage = decryptInCFB(encryptedMessage);
        } else if (encryptionType.toLowerCase() === 'ofb') {
            encryptedMessage = encryptInOFB(message);
            decryptedMessage = decryptInOFB(encryptedMessage);
        } else {
            console.log('Invalid encryption type. Please enter ECB, CFB or OFB.');
            rl.close();
            return;
        }

        console.log(`Encrypted message: ${encryptedMessage}`);
        console.log(`Decrypted message: ${decryptedMessage}`);

        rl.close();
    });
});