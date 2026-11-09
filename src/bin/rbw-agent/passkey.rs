use anyhow::Context as _;

type State = std::sync::Arc<tokio::sync::Mutex<crate::state::State>>;

fn client(config: &rbw::config::Config) -> rbw::api::Client {
    rbw::api::Client::new(
        &config.base_url(),
        &config.identity_url(),
        &config.ui_url(),
        config.client_cert_path(),
    )
}

async fn pin(
    config: &rbw::config::Config,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<rbw::locked::Password> {
    let pin = rbw::pinentry::getpin(
        &config.pinentry,
        "Security key PIN",
        &format!("Unlock {} with your security key. Enter its PIN, then touch the flashing key.", rbw::passkey::origin(config)?),
        None,
        environment,
        true,
    ).await?;
    anyhow::ensure!(
        !pin.password().is_empty(),
        "security-key PIN entry was cancelled"
    );
    Ok(pin)
}

/// Probe failures count as present so the passkey path reports the error.
pub async fn security_key_present(config: &rbw::config::Config) -> bool {
    match rbw::passkey::security_key_count(config).await {
        Ok(count) => count > 0,
        Err(e) => {
            eprintln!("{e:#}");
            true
        }
    }
}

pub async fn login(
    state: State,
    environment: &rbw::protocol::Environment,
    mut db: rbw::db::Db,
) -> anyhow::Result<()> {
    let config = rbw::config::Config::load_async().await?;
    let email = config.email.as_deref().context("email address not set")?;
    let pin = pin(&config, environment).await?;
    let client = client(&config);
    let challenge = client.passkey_challenge().await?;
    let relying_party_id = challenge.options["rpId"]
        .as_str()
        .context("server did not supply a relying-party ID")?
        .to_string();
    let assertion =
        rbw::passkey::assert(&config, challenge.options, &pin).await?;
    drop(pin);
    let response = client
        .login_with_passkey(
            &rbw::config::device_id(&config).await?,
            &challenge.token,
            &assertion.device_response,
        )
        .await?;
    rbw::passkey::check_account(&response.access_token, email)?;
    let credential = response
        .decryption
        .web_authn_prf_option
        .filter(|option| {
            rbw::passkey::same_credential(
                &option.credential_id,
                &assertion.credential_id,
            )
        })
        .context("this passkey is not enabled for vault encryption")?;
    let key = rbw::passkey::decrypt_user_key(&credential, &assertion)?;
    let (
        access_token,
        (
            protected_key,
            protected_private_key,
            protected_org_keys,
            entries,
            options,
        ),
    ) = rbw::actions::sync(&response.access_token, &response.refresh_token)
        .await?;
    let (key, org_keys) = rbw::actions::unlock_with_key(
        key,
        &protected_private_key,
        &protected_org_keys,
    )?;
    let credential = match options {
        Some(options) => options
            .into_iter()
            .find(|option| {
                rbw::passkey::same_credential(
                    &option.credential_id,
                    &credential.credential_id,
                )
            })
            .context("passkey was removed while logging in")?,
        None => credential,
    };
    db.access_token = Some(access_token.unwrap_or(response.access_token));
    db.refresh_token = Some(response.refresh_token);
    db.protected_key = Some(protected_key);
    db.protected_private_key = Some(protected_private_key);
    db.protected_org_keys = protected_org_keys;
    db.entries = entries;
    db.passkey = Some(rbw::passkey::CachedUnlock {
        origin: rbw::passkey::origin(&config)?,
        relying_party_id,
        credential,
    });
    // Cached so master-password unlock still works offline without the key.
    match rbw::actions::prelogin(email).await {
        Ok((kdf, iterations, memory, parallelism)) => {
            db.kdf = Some(kdf);
            db.iterations = Some(iterations);
            db.memory = memory;
            db.parallelism = parallelism;
        }
        Err(e) => eprintln!("failed to fetch kdf parameters: {e:#}"),
    }
    db.save_async(&config.server_name(), email).await?;
    let mut state = state.lock().await;
    state.set_master_password_reprompt(&db.entries);
    state.priv_key = Some(key);
    state.org_keys = Some(org_keys);
    Ok(())
}

pub async fn unlock(
    state: State,
    environment: &rbw::protocol::Environment,
    db: &rbw::db::Db,
) -> anyhow::Result<()> {
    let config = rbw::config::Config::load_async().await?;
    let cached = db
        .passkey
        .as_ref()
        .context("no cached passkey; log in with a passkey first")?;
    let request = cached.request(&config)?;
    let pin = pin(&config, environment).await?;
    let assertion = rbw::passkey::assert(&config, request, &pin).await?;
    drop(pin);
    let key = rbw::passkey::decrypt_user_key(&cached.credential, &assertion)?;
    let (key, org_keys) = rbw::actions::unlock_with_key(
        key,
        db.protected_private_key
            .as_deref()
            .context("missing encrypted account private key; sync first")?,
        &db.protected_org_keys,
    )?;
    let mut state = state.lock().await;
    state.priv_key = Some(key);
    state.org_keys = Some(org_keys);
    Ok(())
}
