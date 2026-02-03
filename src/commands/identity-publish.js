const { Command } = require('commander');
const fs = require('fs');
const crypto = require('crypto');

// Lazy load heavy dependencies
let bitcoin, bip39, bip32, ecc;

function loadDeps() {
  if (!bitcoin) {
    bitcoin = require('bitcoinjs-lib');
    bip39 = require('bip39');
    const { BIP32Factory } = require('bip32');
    ecc = require('tiny-secp256k1');
    bip32 = BIP32Factory(ecc);
  }
}

async function fetchJSON(url) {
  const https = require('https');
  const http = require('http');
  const client = url.startsWith('https') ? https : http;
  
  return new Promise((resolve, reject) => {
    client.get(url, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve(data);
        }
      });
    }).on('error', reject);
  });
}

async function postData(url, data) {
  const https = require('https');
  const urlObj = new URL(url);
  
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: urlObj.hostname,
      path: urlObj.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' }
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

const command = new Command('publish')
  .description('Publish identity claim to Bitcoin (OP_RETURN)')
  .argument('<file>', 'Identity claim JSON file')
  .option('--testnet', 'Use Bitcoin testnet')
  .option('--seed <mnemonic>', 'BIP39 seed phrase for signing')
  .option('--dry-run', 'Show transaction data without broadcasting')
  .option('--fee-rate <sats>', 'Fee rate in sat/vB', '10')
  .action(async (file, options) => {
    try {
      loadDeps();
      
      const content = fs.readFileSync(file, 'utf8');
      const identity = JSON.parse(content);
      
      const network = options.testnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;
      const apiBase = options.testnet 
        ? 'https://blockstream.info/testnet/api'
        : 'https://blockstream.info/api';
      
      // Create the OP_RETURN data (full fingerprint per ATP-RFC-0001)
      const fingerprint = identity.gpg.fingerprint;
      const opReturnData = `ATP:0.4:id:${fingerprint}`;
      const opReturnBuffer = Buffer.from(opReturnData);
      
      console.log('\n=== ATP Identity Publication ===\n');
      console.log('Network:', options.testnet ? 'TESTNET' : 'MAINNET');
      console.log('Agent:', identity.name);
      console.log('GPG:', identity.gpg.fingerprint);
      console.log('Wallet:', identity.wallet.address);
      console.log('');
      console.log('OP_RETURN data:', opReturnData);
      console.log('OP_RETURN hex:', opReturnBuffer.toString('hex'));
      console.log('');
      
      if (options.dryRun) {
        console.log('DRY RUN - Transaction not broadcast\n');
        return;
      }
      
      if (!options.seed) {
        console.log('To broadcast, provide --seed <mnemonic>');
        console.log('Example: --seed "word1 word2 ... word24"');
        return;
      }
      
      // Derive key from seed
      const seed = bip39.mnemonicToSeedSync(options.seed);
      const root = bip32.fromSeed(seed, network);
      const child = root.derivePath("m/84'/0'/0'/0/0");
      const keyPair = {
        publicKey: Buffer.from(child.publicKey),
        privateKey: Buffer.from(child.privateKey)
      };
      
      // Get UTXOs
      console.log('Fetching UTXOs...');
      const utxos = await fetchJSON(`${apiBase}/address/${identity.wallet.address}/utxo`);
      
      if (!utxos || utxos.length === 0) {
        console.log('No UTXOs found. Fund the wallet first.');
        if (options.testnet) {
          console.log('Testnet faucet: https://signetfaucet.com/ or https://testnet-faucet.mempool.co/');
        }
        return;
      }
      
      console.log(`Found ${utxos.length} UTXO(s)`);
      
      // Build transaction
      const psbt = new bitcoin.Psbt({ network });
      
      // Add input (use first UTXO)
      const utxo = utxos[0];
      const txHex = await fetchJSON(`${apiBase}/tx/${utxo.txid}/hex`);
      
      psbt.addInput({
        hash: utxo.txid,
        index: utxo.vout,
        witnessUtxo: {
          script: bitcoin.address.toOutputScript(identity.wallet.address, network),
          value: BigInt(utxo.value)
        }
      });
      
      // Calculate fee (rough estimate)
      const feeRate = parseInt(options.feeRate);
      const estimatedSize = 150; // bytes for 1-in-2-out segwit
      const fee = feeRate * estimatedSize;
      
      // Add OP_RETURN output
      const embed = bitcoin.payments.embed({ data: [opReturnBuffer] });
      psbt.addOutput({
        script: embed.output,
        value: BigInt(0)
      });
      
      // Add change output
      const change = utxo.value - fee;
      if (change < 546) {
        console.log('Insufficient funds for fee. Need at least', fee + 546, 'sats');
        return;
      }
      
      psbt.addOutput({
        address: identity.wallet.address,
        value: BigInt(change)
      });
      
      console.log('Fee:', fee, 'sats');
      console.log('Change:', change, 'sats');
      
      // Sign
      psbt.signInput(0, {
        publicKey: keyPair.publicKey,
        sign: (hash) => {
          return Buffer.from(ecc.sign(hash, keyPair.privateKey));
        }
      });
      
      psbt.finalizeAllInputs();
      const tx = psbt.extractTransaction();
      const txHexFinal = tx.toHex();
      
      console.log('\nTransaction ID:', tx.getId());
      console.log('Transaction hex:', txHexFinal.slice(0, 64) + '...');
      
      // Broadcast
      console.log('\nBroadcasting...');
      const result = await postData(`${apiBase}/tx`, txHexFinal);
      
      if (result.status === 200) {
        console.log('✅ SUCCESS! Transaction broadcast.');
        console.log('TXID:', result.body);
        console.log('');
        console.log('View:', options.testnet 
          ? `https://blockstream.info/testnet/tx/${result.body}`
          : `https://blockstream.info/tx/${result.body}`);
      } else {
        console.log('❌ Broadcast failed:', result.body);
      }
      
    } catch (err) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

module.exports = command;
