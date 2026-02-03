const { Command } = require('commander');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const command = new Command('create')
  .description('Create a new ATP identity claim')
  .requiredOption('-n, --name <name>', 'Agent name')
  .requiredOption('-g, --gpg <fingerprint>', 'GPG key fingerprint')
  .requiredOption('-w, --wallet <address>', 'Bitcoin wallet address')
  .option('-k, --keyserver <url>', 'GPG keyserver', 'keys.openpgp.org')
  .option('--moltbook <handle>', 'Moltbook handle')
  .option('--twitter <handle>', 'Twitter handle')
  .option('--github <handle>', 'GitHub handle')
  .option('--wallet-sig <signature>', 'Pre-signed wallet proof (if already signed)')
  .option('-o, --output <file>', 'Output file (default: stdout)')
  .option('-t, --timestamp <unix>', 'Unix timestamp (default: now)')
  .action(async (options) => {
    try {
      const identity = await createIdentity(options);
      
      const output = JSON.stringify(identity, null, 2);
      
      if (options.output) {
        fs.writeFileSync(options.output, output);
        console.error(`Identity claim written to ${options.output}`);
      } else {
        console.log(output);
      }
    } catch (err) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

async function createIdentity(options) {
  const timestamp = options.timestamp ? parseInt(options.timestamp) : Math.floor(Date.now() / 1000);
  
  // Build platforms object
  const platforms = {};
  if (options.moltbook) platforms.moltbook = options.moltbook;
  if (options.twitter) platforms.twitter = options.twitter;
  if (options.github) platforms.github = options.github;
  
  // Build wallet proof message
  const walletProofMessage = `ATP:0.4:identity:${options.name}:${options.gpg}:${timestamp}`;
  
  // Create the identity object (without signature first)
  const identity = {
    atp: '0.4',
    type: 'identity',
    name: options.name,
    gpg: {
      fingerprint: options.gpg.toUpperCase().replace(/\s/g, ''),
      keyserver: options.keyserver
    },
    wallet: {
      address: options.wallet,
      proof: {
        message: walletProofMessage,
        signature: options.walletSig || '<SIGN_THIS_MESSAGE_WITH_BITCOIN_WALLET>'
      }
    },
    platforms: platforms,
    binding_proofs: [],
    created: timestamp
  };
  
  // If no wallet signature provided, show instructions
  if (!options.walletSig) {
    console.error('\n⚠️  Wallet signature required!');
    console.error('Sign this message with your Bitcoin wallet:\n');
    console.error(`  "${walletProofMessage}"\n`);
    console.error('Then re-run with --wallet-sig "<signature>"\n');
  }
  
  // Sign with GPG - sign the identity WITHOUT the signature field
  const payloadToSign = JSON.stringify(identity, null, 2);
  
  try {
    // Write payload to temp file to avoid shell escaping issues
    const tmpFile = `/tmp/atp-sign-${Date.now()}.json`;
    fs.writeFileSync(tmpFile, payloadToSign);
    
    // Create detached signature
    const sigResult = execSync(
      `gpg --armor --detach-sign --local-user ${options.gpg} ${tmpFile} 2>/dev/null && cat ${tmpFile}.asc`,
      { encoding: 'utf8' }
    );
    
    // Cleanup
    fs.unlinkSync(tmpFile);
    try { fs.unlinkSync(`${tmpFile}.asc`); } catch (e) {}
    
    identity.signature = sigResult.trim();
  } catch (err) {
    console.error('\n⚠️  GPG signing failed. Make sure you have the private key for:', options.gpg);
    identity.signature = '<GPG_SIGNATURE_REQUIRED>';
  }
  
  return identity;
}

module.exports = command;
