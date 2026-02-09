#!/usr/bin/env node

import { Command } from 'commander';
import identity from './commands/identity.js';
import verifyCmd from './commands/verify.js';
import supersede from './commands/supersede.js';
import revoke from './commands/revoke.js';
import attest from './commands/attest.js';
import attRevoke from './commands/att-revoke.js';
import heartbeat from './commands/heartbeat.js';
import receipt from './commands/receipt.js';

const program = new Command();

program
  .name('atp')
  .version('1.0.0')
  .description('Agent Trust Protocol CLI — identity, attestations, receipts, inscriptions');

program.addCommand(identity);
program.addCommand(verifyCmd);
program.addCommand(supersede);
program.addCommand(revoke);
program.addCommand(attest);
program.addCommand(attRevoke);
program.addCommand(heartbeat);
program.addCommand(receipt);

program.parse();
