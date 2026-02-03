const { Command } = require('commander');
const fs = require('fs');

const command = new Command('show')
  .description('Display ATP identity claim details')
  .argument('<file>', 'Identity claim JSON file')
  .option('--json', 'Output as JSON')
  .action(async (file, options) => {
    try {
      const content = fs.readFileSync(file, 'utf8');
      const identity = JSON.parse(content);
      
      if (options.json) {
        console.log(JSON.stringify(identity, null, 2));
        return;
      }
      
      console.log('\n=== ATP Identity Claim ===\n');
      console.log(`Version:     ${identity.atp}`);
      console.log(`Type:        ${identity.type}`);
      console.log(`Name:        ${identity.name}`);
      console.log(`Created:     ${new Date(identity.created * 1000).toISOString()}`);
      
      console.log('\nGPG:');
      console.log(`  Fingerprint: ${identity.gpg?.fingerprint || 'N/A'}`);
      console.log(`  Keyserver:   ${identity.gpg?.keyserver || 'N/A'}`);
      
      console.log('\nWallet:');
      console.log(`  Address: ${identity.wallet?.address || 'N/A'}`);
      console.log(`  Proof:   ${identity.wallet?.proof?.signature ? 'Present' : 'Missing'}`);
      
      if (identity.platforms && Object.keys(identity.platforms).length > 0) {
        console.log('\nPlatforms:');
        for (const [platform, handle] of Object.entries(identity.platforms)) {
          console.log(`  ${platform}: ${handle}`);
        }
      }
      
      if (identity.binding_proofs && identity.binding_proofs.length > 0) {
        console.log('\nBinding Proofs:');
        for (const proof of identity.binding_proofs) {
          console.log(`  ${proof.platform}: ${proof.url}`);
        }
      }
      
      console.log('\nSignature:', identity.signature ? 'Present' : 'Missing');
      console.log('');
      
    } catch (err) {
      console.error('Error:', err.message);
      process.exit(1);
    }
  });

module.exports = command;
