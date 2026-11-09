use anyhow::Context as _;
use sha2::Digest as _;
use tokio::io::AsyncWriteExt as _;
use zeroize::{Zeroize as _, Zeroizing};

#[derive(serde::Deserialize)]
pub struct Challenge {
    pub options: serde_json::Value,
    pub token: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PrfOption {
    #[serde(alias = "CredentialId")]
    pub credential_id: String,
    #[serde(alias = "EncryptedPrivateKey")]
    pub encrypted_private_key: String,
    #[serde(alias = "EncryptedUserKey")]
    pub encrypted_user_key: String,
}

#[derive(serde::Deserialize, Default, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DecryptionOptions {
    #[serde(alias = "WebAuthnPrfOption")]
    pub web_authn_prf_option: Option<PrfOption>,
    #[serde(alias = "WebAuthnPrfOptions")]
    pub web_authn_prf_options: Option<Vec<PrfOption>>,
}

#[derive(serde::Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(
        rename = "UserDecryptionOptions",
        alias = "userDecryptionOptions"
    )]
    pub decryption: DecryptionOptions,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct CachedUnlock {
    pub origin: String,
    pub relying_party_id: String,
    pub credential: PrfOption,
}

pub struct Assertion {
    pub credential_id: String,
    pub device_response: String,
    pub prf: crate::locked::Vec,
}

#[derive(serde::Serialize)]
struct HelperRequest<'a> {
    origin: String,
    options: serde_json::Value,
    pin: Option<&'a str>,
}

#[derive(serde::Deserialize)]
struct HelperResponse {
    assertion: serde_json::Value,
    prf: String,
}

pub fn origin(config: &crate::config::Config) -> anyhow::Result<String> {
    let url = url::Url::parse(&config.ui_url())?;
    anyhow::ensure!(
        url.scheme() == "https",
        "passkey login requires an HTTPS web vault URL"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "web vault URL must not contain credentials"
    );
    Ok(url.origin().ascii_serialization())
}

pub fn prf_salt() -> String {
    crate::base64::encode_url_safe_no_pad(sha2::Sha256::digest(
        b"passwordless-login",
    ))
}

pub fn decode_id(value: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(
        value
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_"),
    )?)
}

pub fn same_credential(first: &str, second: &str) -> bool {
    match (decode_id(first), decode_id(second)) {
        (Ok(first), Ok(second)) => first == second,
        _ => false,
    }
}

async fn probe_helper(
    config: &crate::config::Config,
    arg: &str,
) -> anyhow::Result<String> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(&config.passkey_helper)
            .arg(arg)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("security-key probe timed out")?
    .context("could not start rbw-passkey; install the passkey helper")?;
    anyhow::ensure!(
        output.status.success(),
        "security-key probe failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(std::str::from_utf8(&output.stdout)?.trim().to_string())
}

pub async fn security_key_count(
    config: &crate::config::Config,
) -> anyhow::Result<usize> {
    probe_helper(config, "--probe")
        .await?
        .parse()
        .context("invalid security-key probe response")
}

/// False when the key verifies the user itself, e.g. with a fingerprint or
/// its own screen lock, and has no client PIN to fall back to.
pub async fn pin_required(
    config: &crate::config::Config,
) -> anyhow::Result<bool> {
    probe_helper(config, "--probe-pin")
        .await?
        .parse()
        .context("invalid security-key PIN probe response")
}

pub async fn assert(
    config: &crate::config::Config,
    mut options: serde_json::Value,
    pin: Option<&crate::locked::Password>,
) -> anyhow::Result<Assertion> {
    options["userVerification"] = serde_json::json!("required");
    options["extensions"] =
        serde_json::json!({"prf": {"eval": {"first": prf_salt()}}});
    options["timeout"] = serde_json::json!(120_000);
    let request = Zeroizing::new(serde_json::to_vec(&HelperRequest {
        origin: origin(config)?,
        options,
        pin: pin
            .map(|pin| std::str::from_utf8(pin.password()))
            .transpose()?,
    })?);
    let mut child = tokio::process::Command::new(&config.passkey_helper)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("could not start rbw-passkey; install the passkey helper")?;
    let mut stdin = child
        .stdin
        .take()
        .context("passkey helper stdin unavailable")?;
    stdin.write_all(&request).await?;
    drop(stdin);
    drop(request);
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(130),
        child.wait_with_output(),
    )
    .await
    .context("security-key operation timed out")??;
    let stdout = Zeroizing::new(output.stdout);
    anyhow::ensure!(
        output.status.success(),
        "security-key operation failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let mut result: HelperResponse = serde_json::from_slice(&stdout)
        .context("invalid passkey helper response")?;
    let mut prf =
        Zeroizing::new(decode_id(&result.prf).context("invalid PRF output")?);
    result.prf.zeroize();
    anyhow::ensure!(
        prf.len() == 32 && prf.iter().any(|b| *b != 0),
        "security key did not return a valid PRF output"
    );
    let credential_id = result.assertion["rawId"]
        .as_str()
        .context("assertion has no credential ID")?
        .to_string();
    let mut secret = crate::locked::Vec::new();
    secret.extend(prf.iter().copied());
    prf.zeroize();
    Ok(Assertion {
        credential_id,
        device_response: serde_json::to_string(&result.assertion)?,
        prf: secret,
    })
}

pub fn derive_key(prf: &[u8]) -> anyhow::Result<crate::locked::Keys> {
    anyhow::ensure!(
        prf.len() == 32 && prf.iter().any(|b| *b != 0),
        "invalid PRF output"
    );
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(prf)
        .map_err(|_| anyhow::anyhow!("invalid PRF key"))?;
    let mut key = crate::locked::Vec::new();
    key.extend(std::iter::repeat_n(0, 64));
    hkdf.expand(b"enc", &mut key.data_mut()[..32])
        .map_err(|_| anyhow::anyhow!("PRF key expansion failed"))?;
    hkdf.expand(b"mac", &mut key.data_mut()[32..])
        .map_err(|_| anyhow::anyhow!("PRF key expansion failed"))?;
    Ok(crate::locked::Keys::new(key))
}

pub fn decrypt_user_key(
    option: &PrfOption,
    assertion: &Assertion,
) -> anyhow::Result<crate::locked::Keys> {
    anyhow::ensure!(
        same_credential(&option.credential_id, &assertion.credential_id),
        "passkey does not match the encrypted vault key"
    );
    let prf_key = derive_key(assertion.prf.data())?;
    let encrypted_private_key = crate::cipherstring::CipherString::new(
        &option.encrypted_private_key,
    )?;
    anyhow::ensure!(
        matches!(
            &encrypted_private_key,
            crate::cipherstring::CipherString::Symmetric { mac: Some(_), .. }
        ),
        "PRF-encrypted private key must have an authentication tag"
    );
    let private_key =
        encrypted_private_key.decrypt_locked_symmetric(&prf_key)?;
    let key =
        crate::cipherstring::CipherString::new(&option.encrypted_user_key)?
            .decrypt_locked_asymmetric(&crate::locked::PrivateKey::new(
            private_key,
        ))?;
    anyhow::ensure!(
        key.data().len() == 64,
        "invalid decrypted vault-key length"
    );
    Ok(crate::locked::Keys::new(key))
}

pub fn check_account(
    access_token: &str,
    expected_email: &str,
) -> anyhow::Result<()> {
    let payload = access_token
        .split('.')
        .nth(1)
        .context("invalid access token")?;
    let claims: serde_json::Value =
        serde_json::from_slice(&decode_id(payload)?)?;
    let email = claims["email"]
        .as_str()
        .context("access token has no email")?;
    anyhow::ensure!(
        email.trim().eq_ignore_ascii_case(expected_email.trim()),
        "selected passkey belongs to a different account"
    );
    Ok(())
}

impl CachedUnlock {
    pub fn request(
        &self,
        config: &crate::config::Config,
    ) -> anyhow::Result<serde_json::Value> {
        anyhow::ensure!(self.origin == origin(config)?, "cached passkey belongs to a different web vault origin; log in again");
        let challenge: [u8; 32] = rand::random();
        Ok(serde_json::json!({
            "challenge": crate::base64::encode_url_safe_no_pad(challenge),
            "rpId": self.relying_party_id,
            "allowCredentials": [{"type": "public-key", "id": self.credential.credential_id}],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        prf: String,
        derived_key: String,
        user_key: String,
        option: PrfOption,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../tests/fixtures/passkey.json"))
            .unwrap()
    }

    fn assertion(fixture: &Fixture) -> Assertion {
        let mut prf = crate::locked::Vec::new();
        prf.extend(crate::base64::decode(&fixture.prf).unwrap().into_iter());
        Assertion {
            credential_id: fixture.option.credential_id.clone(),
            device_response: String::new(),
            prf,
        }
    }

    #[test]
    fn passkey_decrypts_independent_python_fixture() {
        let fixture = fixture();
        let assertion = assertion(&fixture);
        let derived = derive_key(assertion.prf.data()).unwrap();
        let expected = crate::base64::decode(&fixture.derived_key).unwrap();
        assert_eq!(derived.enc_key(), &expected[..32]);
        assert_eq!(derived.mac_key(), &expected[32..]);
        let key = decrypt_user_key(&fixture.option, &assertion).unwrap();
        let expected = crate::base64::decode(&fixture.user_key).unwrap();
        assert_eq!(key.enc_key(), &expected[..32]);
        assert_eq!(key.mac_key(), &expected[32..]);
    }

    #[test]
    fn passkey_rejects_wrong_key_and_modified_ciphertext() {
        let mut fixture = fixture();
        let mut assertion = assertion(&fixture);
        assertion.credential_id = "BAUG".to_string();
        assert!(decrypt_user_key(&fixture.option, &assertion).is_err());
        assertion
            .credential_id
            .clone_from(&fixture.option.credential_id);
        assertion.prf.data_mut()[0] ^= 1;
        assert!(decrypt_user_key(&fixture.option, &assertion).is_err());
        assertion.prf.data_mut()[0] ^= 1;
        fixture.option.encrypted_private_key.push('A');
        assert!(decrypt_user_key(&fixture.option, &assertion).is_err());
        fixture.option.encrypted_private_key = fixture
            .option
            .encrypted_private_key
            .rsplit_once('|')
            .unwrap()
            .0
            .to_string();
        assert!(decrypt_user_key(&fixture.option, &assertion).is_err());
        assert!(derive_key(&[0; 32]).is_err());
        assert!(derive_key(&[1; 31]).is_err());
    }

    #[test]
    fn passkey_cached_unlock_is_bound_to_origin_and_credential() {
        let mut config = crate::config::Config::new();
        config.base_url = Some("https://vault.example.test:8222".to_string());
        let cached = CachedUnlock {
            origin: origin(&config).unwrap(),
            relying_party_id: "vault.example.test".to_string(),
            credential: fixture().option,
        };
        let first = cached.request(&config).unwrap();
        let second = cached.request(&config).unwrap();
        assert_ne!(first["challenge"], second["challenge"]);
        assert_eq!(first["allowCredentials"][0]["id"], "AQID");
        config.base_url = Some("https://other.example.test".to_string());
        assert!(cached.request(&config).is_err());
        config.base_url = Some("http://vault.example.test".to_string());
        assert!(origin(&config).is_err());
    }

    #[test]
    fn passkey_response_accepts_server_field_names_and_checks_account() {
        let response: LoginResponse = serde_json::from_value(serde_json::json!({
            "access_token": "token", "refresh_token": "refresh",
            "UserDecryptionOptions": {"WebAuthnPrfOption": {
                "CredentialId": "AQID", "EncryptedPrivateKey": "encrypted",
                "EncryptedUserKey": "encrypted"
            }}
        })).unwrap();
        assert_eq!(
            response
                .decryption
                .web_authn_prf_option
                .unwrap()
                .credential_id,
            "AQID"
        );
        let payload = crate::base64::encode_url_safe_no_pad(
            br#"{"email":"user@example.test"}"#,
        );
        let token = format!("header.{payload}.signature");
        assert!(check_account(&token, " USER@example.test ").is_ok());
        assert!(check_account(&token, "other@example.test").is_err());
        assert!(check_account("invalid", "user@example.test").is_err());
        assert!(same_credential("-_8", "+/8="));
        assert!(!same_credential("!", "!"));
    }

    #[test]
    fn passkey_cache_does_not_require_master_password_kdf() {
        let mut db = crate::db::Db::new();
        db.access_token = Some("token".to_string());
        db.refresh_token = Some("refresh".to_string());
        assert!(db.needs_login());
        db.passkey = Some(CachedUnlock {
            origin: "https://vault.example.test".to_string(),
            relying_party_id: "vault.example.test".to_string(),
            credential: fixture().option,
        });
        assert!(!db.needs_login());
        db.access_token = None;
        assert!(db.needs_login());
    }
}
