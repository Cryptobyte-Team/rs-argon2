# Argon2 with Rust for NodeJS
This is a Rust Argon2 Implementation for NodeJS that wraps the popular [argon2 Rust crate](https://crates.io/crates/argon2) with [Neon](https://neon-bindings.com) to create a NodeJS library. Note that this is currently **slower** than popular alternatives such as [argon2](https://github.com/ranisalt/node-argon2) (C++).

We're new to Rust and as such there are some fairly large issues that could be improved upon by more experienced Rustaceans such as
1. Does not handle errors well
2. Async methods need work
3. General speed improvements to existing code

Latest Speed Test (using `example/`)
```
Loaded 1000 passwords!
Computing hashes (async - argon2)..
Hashed 1000 Passwords..: 4.730s
Verifying hashes (async - argon2)..
Verified 1000 Hashes..: 4.674s
Computing hashes (async)..
Hashed 1000 Passwords..: 5.497s
Verifying hashes (async)..
Verified 1000 Hashes..: 5.508s
Computing hashes (sync)..
Hashed 1000 Passwords..: 5.498s
Verifying hashes (sync)..
Verified 1000 Hashes..: 5.525s
```
