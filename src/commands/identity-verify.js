const { Command } = require('commander');
const { execSync } = require('child_process');
const fs = require('fs');

const command = new Command('verify')
  .description('Verify an ATP identity claim')
  .argument('<file>', 'Identity claim JSON file')
  .option('--skip-wallet', 'Skip wallet signature verification')
  .option('--skip-gpg', 'Skip GPG signature verification')
  .option('-v, --verbose', 'Verbose output')
  .action(async (file, options) => {
    try {
      const result = await verifyIdentity(file, options);
      
      console.log('\n=== ATP Identity Verification ===\n');
      console.log(`Agent: ${result.name}`);
      console.log(`GPG:   ${result.gpg}`);
      console.log(`Wallet: ${result.wallet}\n`);
      
      console.log('Checks:');
      for (const check of result.checks) {
        const icon = check.pass ? '✅' : '❌';
        console.log(`  ${icon} ${check.name}: ${check.message}`);
      }
      
      console.log('');
      if (result.valid) {
        console.log('✅ Identity claim is VALID\n');
        process.exit(0);
      } else {
        console.log('❌ Identity claim is INVALID\n');
        process.exit(1);
      }
    } catch (err) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

async function verifyIdentity(file, options) {
  // Read and parse identity
  const content = fs.readFileSync(file, 'utf8');
  const identity = JSON.parse(content);
  
  const checks = [];
  let valid = true;
  
  // Check structure
  if (identity.atp !== '0.4') {
    checks.push({ name: 'Version', pass: false, message: `Expected 0.4, got ${identity.atp}` });
    valid = false;
  } else {
    checks.push({ name: 'Version', pass: true, message: '0.4' });
  }
  
  if (identity.type !== 'identity') {
    checks.push({ name: 'Type', pass: false, message: `Expected identity, got ${identity.type}` });
    valid = false;
  } else {
    checks.push({ name: 'Type', pass: true, message: 'identity' });
  }
  
  // Verify GPG signature
  if (!options.skipGpg && identity.signature && !identity.signature.includes('REQUIRED')) {
    try {
      // Create temp file with payload (without signature)
      const payloadObj = { ...identity };
      delete payloadObj.signature;
      const payload = JSON.stringify(payloadObj, null, 2);
      
      const tmpPayload = `/tmp/atp-verify-payload-${Date.now()}.json`;
      const tmpSig = `/tmp/atp-verify-sig-${Date.now()}.asc`;
      
      fs.writeFileSync(tmpPayload, payload);
      fs.writeFileSync(tmpSig, identity.signature);
      
      try {
        execSync(`gpg --verify ${tmpSig} ${tmpPayload} 2>&1`, { encoding: 'utf8' });
        checks.push({ name: 'GPG Signature', pass: true, message: 'Valid' });
      } catch (gpgErr) {
        checks.push({ name: 'GPG Signature', pass: false, message: 'Invalid or untrusted' });
        valid = false;
      }
      
      // Cleanup
      fs.unlinkSync(tmpPayload);
      fs.unlinkSync(tmpSig);
    } catch (err) {
      checks.push({ name: 'GPG Signature', pass: false, message: err.message });
      valid = false;
    }
  } else if (options.skipGpg) {
    checks.push({ name: 'GPG Signature', pass: true, message: 'Skipped' });
  } else {
    checks.push({ name: 'GPG Signature', pass: false, message: 'Missing or placeholder' });
    valid = false;
  }
  
  // Verify wallet signature (placeholder - would need bitcoin-message library)
  if (!options.skipWallet && identity.wallet?.proof?.signature) {
    if (identity.wallet.proof.signature.includes('SIGN_THIS')) {
      checks.push({ name: 'Wallet Signature', pass: false, message: 'Not signed yet' });
      valid = false;
    } else {
      // TODO: Implement actual Bitcoin message verification
      checks.push({ name: 'Wallet Signature', pass: true, message: 'Present (verification not implemented yet)' });
    }
  } else if (options.skipWallet) {
    checks.push({ name: 'Wallet Signature', pass: true, message: 'Skipped' });
  } else {
    checks.push({ name: 'Wallet Signature', pass: false, message: 'Missing' });
    valid = false;
  }
  
  // Check required fields
  if (!identity.name) {
    checks.push({ name: 'Name', pass: false, message: 'Missing' });
    valid = false;
  } else {
    checks.push({ name: 'Name', pass: true, message: identity.name });
  }
  
  if (!identity.gpg?.fingerprint) {
    checks.push({ name: 'GPG Fingerprint', pass: false, message: 'Missing' });
    valid = false;
  } else {
    checks.push({ name: 'GPG Fingerprint', pass: true, message: identity.gpg.fingerprint.slice(0, 16) + '...' });
  }
  
  return {
    valid,
    checks,
    name: identity.name,
    gpg: identity.gpg?.fingerprint,
    wallet: identity.wallet?.address
  };
}

module.exports = command;
