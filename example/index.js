const fs = require('fs');
const { 
  hash,
  hash_sync, 
  verify,
  verify_sync 

} = require('../');

const argon2 = require('argon2');

const runArgon2 = async(passwords) => {
  const hashes = [];

  console.log(`Computing hashes (async - argon2)..`);

  console.time(`Hashed ${passwords.length - 1} Passwords..`);
  for (let i = 0; i < passwords.length; i++) {
    const password = passwords[i];
    hashes[i] = await argon2.hash(password);
  }

  console.timeEnd(`Hashed ${passwords.length - 1} Passwords..`);

  console.log(`Verifying hashes (async - argon2)..`);

  console.time(`Verified ${hashes.length - 1} Hashes..`);
  for (let i = 0; i < hashes.length; i++) {
    const hash = hashes[i];
    await argon2.verify(hash, passwords[i]);
  }

  console.timeEnd(`Verified ${hashes.length - 1} Hashes..`);
};

const runSync = (passwords) => {
  const hashes = [];

  console.log(`Computing hashes (sync)..`);

  console.time(`Hashed ${passwords.length - 1} Passwords..`);

  for (let i = 0; i < passwords.length; i++) {
    const password = passwords[i];
    hashes[i] = hash_sync(password);
  }

  console.timeEnd(`Hashed ${passwords.length - 1} Passwords..`);

  console.log(`Verifying hashes (sync)..`);

  console.time(`Verified ${hashes.length - 1} Hashes..`);

  for (let i = 0; i < hashes.length; i++) {
    const hash = hashes[i];
    verify_sync(passwords[i], hash);
  }

  console.timeEnd(`Verified ${hashes.length - 1} Hashes..`);
};

const runAsync = async(passwords) => {
  const hashes = [];

  console.log(`Computing hashes (async)..`);

  console.time(`Hashed ${passwords.length - 1} Passwords..`);
  for (let i = 0; i < passwords.length; i++) {
    const password = passwords[i];
    hashes[i] = await hash(password);
  }

  console.timeEnd(`Hashed ${passwords.length - 1} Passwords..`);

  console.log(`Verifying hashes (async)..`);

  console.time(`Verified ${hashes.length - 1} Hashes..`);
  for (let i = 0; i < hashes.length; i++) {
    const hash = hashes[i];
    await verify(passwords[i], hash);
  }

  console.timeEnd(`Verified ${hashes.length - 1} Hashes..`);
};

fs.readFile('passwords.txt', async(err, data) => {
  if (err) throw err;

  const passwords = data.toString().split("\n");

  console.log(`Loaded ${passwords.length - 1} passwords!`);

  await runArgon2(passwords);
  await runAsync(passwords);
  runSync(passwords);
});
