use neon::prelude::*;
use argon2::{
  password_hash::{
    rand_core::OsRng,
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString
  },
  Argon2
};

fn hash(mut cx: FunctionContext) -> JsResult<JsString> {
  let password = cx.argument::<JsString>(0)?;

  let salt = SaltString::generate(&mut OsRng);
  let argon2 = Argon2::default();

  let password_bytes = password.value(&mut cx);
  let password_hash = 
    argon2.hash_password(password_bytes.as_bytes(), &salt);

  let result = match password_hash {
    Ok(hash) => Ok(cx.string(hash.to_string())),
    Err(e) => cx.throw_error(e.to_string())
  };

  result
}

fn verify(mut cx: FunctionContext) -> JsResult<JsBoolean> {
  let password = cx.argument::<JsString>(0)?.value(&mut cx);
  let hash = cx.argument::<JsString>(1)?.value(&mut cx);

  let parse_hash = PasswordHash::new(&hash);
  let parsed_hash = match parse_hash {
    Ok(res) => res,
    Err(err) => panic!("{}", err)
  };

  let matching = 
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash);

  let result = match matching {
    Ok(()) => Ok(cx.boolean(true)),
    Err(_) => Ok(cx.boolean(false))
  };
  
  result
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
  cx.export_function("hash", hash)?;
  cx.export_function("verify", verify)?;
  Ok(())
}