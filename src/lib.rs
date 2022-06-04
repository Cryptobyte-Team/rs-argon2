use neon::prelude::*;
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;
use argon2::{
  password_hash::{
    rand_core::OsRng,
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString
  },
  Argon2
};

fn runtime<'a, C: Context<'a>>(cx: &mut C) -> NeonResult<&'static Runtime> {
  static RUNTIME: OnceCell<Runtime> = OnceCell::new();

  RUNTIME.get_or_try_init(|| Runtime::new().or_else(|err| cx.throw_error(err.to_string())))
}

fn hash(mut cx: FunctionContext) -> JsResult<JsPromise> {
  let password = cx.argument::<JsString>(0)?.value(&mut cx);

  let rt = runtime(&mut cx)?;
  let channel = cx.channel();
  let (deferred, promise) = cx.promise();
  
  rt.spawn(async move {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = 
      argon2.hash_password(password.as_bytes(), &salt);

    let string_hash = password_hash.unwrap().to_string();
    
    deferred.settle_with(&channel, move |mut cx| {
      Ok(cx.string(string_hash))
    });
  });

  Ok(promise)
}

fn hash_sync(mut cx: FunctionContext) -> JsResult<JsString> {
  let password = cx.argument::<JsString>(0)?.value(&mut cx);

  let salt = SaltString::generate(&mut OsRng);
  let argon2 = Argon2::default();

  let password_hash = 
    argon2.hash_password(password.as_bytes(), &salt);

  let result = match password_hash {
    Ok(hash) => Ok(cx.string(hash.to_string())),
    Err(e) => cx.throw_error(e.to_string())
  };

  result
}

fn verify(mut cx: FunctionContext) -> JsResult<JsPromise> {
  let password = cx.argument::<JsString>(0)?.value(&mut cx);
  let hash = cx.argument::<JsString>(1)?.value(&mut cx);

  let rt = runtime(&mut cx)?;
  let channel = cx.channel();
  let (deferred, promise) = cx.promise();
  
  rt.spawn(async move {
    // async
    let parsed_hash = PasswordHash::new(&hash).unwrap();
    let matching = 
      Argon2::default().verify_password(password.as_bytes(), &parsed_hash);

    deferred.settle_with(&channel, move |mut cx| {
      let result = match matching {
        Ok(()) => Ok(cx.boolean(true)),
        Err(_) => Ok(cx.boolean(false))
      };
      
      result
    });
  });

  Ok(promise)
}

fn verify_sync(mut cx: FunctionContext) -> JsResult<JsBoolean> {
  let password = cx.argument::<JsString>(0)?.value(&mut cx);
  let hash = cx.argument::<JsString>(1)?.value(&mut cx);

  let parsed_hash = PasswordHash::new(&hash).unwrap();
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
  cx.export_function("hash_sync", hash_sync)?;
  cx.export_function("verify_sync", verify_sync)?;
  Ok(())
}