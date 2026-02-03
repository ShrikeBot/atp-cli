#!/usr/bin/env node

const { Command } = require('commander');
const pkg = require('../package.json');

const program = new Command();

program
  .name('atp')
  .description('Agent Trust Protocol CLI - identity, attestations, receipts')
  .version(pkg.version);

// Identity commands
program
  .command('identity')
  .description('Manage agent identities')
  .addCommand(require('./commands/identity-create'))
  .addCommand(require('./commands/identity-verify'))
  .addCommand(require('./commands/identity-show'));

// Future: attestation commands
// program.command('attestation')...

// Future: receipt commands  
// program.command('receipt')...

program.parse();
