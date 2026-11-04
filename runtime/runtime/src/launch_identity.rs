//! Runtime's enforceable Minecraft authentication boundary.
//! Credentials from each provider are never interchangeable. In particular,
//! a project/Yggdrasil token is not a Mojang session-server token.
use crate::{MinecraftLaunchCredentials, LaunchPlan};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GameIdentity { Official, Yggdrasil, Offline }

fn valid_uuid(raw: &str) -> bool {
    let s = raw.as_bytes();
    (s.len() == 32 && s.iter().all(u8::is_ascii_hexdigit)) ||
    (s.len() == 36 && s.iter().enumerate().all(|(i,b)| {
        if matches!(i,8|13|18|23) { *b == b'-' } else { b.is_ascii_hexdigit() }
    }))
}
fn valid_name(name: &str) -> bool {
    (3..=16).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn valid_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= 8192 && token.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

pub fn identity(credentials: Option<&MinecraftLaunchCredentials>) -> Result<GameIdentity,String> {
    let Some(c) = credentials else { return Ok(GameIdentity::Offline) };
    if !valid_name(&c.username) || !valid_uuid(&c.uuid) || !valid_token(&c.access_token) {
        return Err("invalid Minecraft player identity or session token".into());
    }
    match c.user_type.as_str() {
        "msa" if c.auth_server_base_url.is_empty() => Ok(GameIdentity::Official),
        "mojang" if !c.auth_server_base_url.is_empty() => {
            let url = reqwest::Url::parse(&c.auth_server_base_url).map_err(|_| "invalid Yggdrasil URL")?;
            let loopback = url.host_str().is_some_and(|v| matches!(v,"localhost"|"127.0.0.1"|"[::1]"));
            if (url.scheme() != "https" && !(url.scheme()=="http" && loopback)) ||
                url.username() != "" || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
                return Err("Yggdrasil authentication requires HTTPS or loopback HTTP".into());
            }
            Ok(GameIdentity::Yggdrasil)
        }
        _ => Err("Minecraft credentials have a mismatched authentication realm".into()),
    }
}

pub fn forbidden_auth_agent(args: &[String]) -> bool {
    args.iter().any(|arg| {
        let x=arg.to_ascii_lowercase();
        x.contains("authlib-injector") || x.starts_with("-dauthlibinjector.")
    })
}

// Metadata and signed project arguments may contain stale identities. Pin one
// authoritative set *after* resolving the version, not before it.
fn remove_pair(args:&mut Vec<String>, key:&str) -> Result<(),String> {
    let mut i=0;
    while i<args.len() {
        if args[i]==key {
            if args.get(i+1).is_none_or(|value|value.starts_with("--")) {
                return Err(format!("malformed {key} in signed game arguments"));
            }
            args.remove(i);
            args.remove(i);
        } else if args[i].starts_with(&format!("{key}=")) {args.remove(i);}
        else {i+=1;}
    }
    Ok(())
}

fn supports_user_type(version: &str) -> bool {
    let mut parts=version.split('.');
    let (Some(major),Some(minor),Some(patch)) =
        (parts.next().and_then(|v|v.parse::<u32>().ok()),parts.next().and_then(|v|v.parse::<u32>().ok()),parts.next())
        else { return false; };
    let p = patch.split(|c:char| !c.is_ascii_digit()).next().unwrap_or("").parse::<u32>().unwrap_or(u32::MAX);
    major == 1 && (minor<21 || (minor==21 && p<=8))
}

pub fn pin_game_identity(plan:&mut LaunchPlan, version:&str, credentials:Option<&MinecraftLaunchCredentials>, offline_username:&str) -> Result<(),String> {
    let mode=identity(credentials)?;
    if mode != GameIdentity::Yggdrasil && forbidden_auth_agent(&plan.jvm_args) {
        return Err("official/offline launches cannot redirect session authentication to Yggdrasil".into());
    }
    for key in ["--username","--uuid","--accessToken","--userType","--xuid"] {
        remove_pair(&mut plan.game_args,key)?;
    }
    match credentials {
        Some(c) => {
            plan.game_args.extend(["--username".into(),c.username.clone(),"--uuid".into(),c.uuid.clone(),"--accessToken".into(),c.access_token.clone()]);
            if supports_user_type(version) {plan.game_args.extend(["--userType".into(),c.user_type.clone()]);}
        }
        None => {
            if !valid_name(offline_username) {return Err("offline Minecraft username must be 3-16 ASCII letters/digits/underscore".into());}
            // An offline game receives no provider credentials and can never
            // generate sessionserver join proof for an online-mode server.
            plan.game_args.extend(["--username".into(),offline_username.into(),"--accessToken".into(),"0".into()]);
            if supports_user_type(version) {plan.game_args.extend(["--userType".into(),"legacy".into()]);}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cred(mode:&str) -> MinecraftLaunchCredentials {
        MinecraftLaunchCredentials{ username:"Player_01".into(),uuid:"11111111222233334444555555555555".into(),access_token:"real.access_token".into(),user_type:mode.into(),auth_server_base_url:if mode=="mojang"{"https://auth.example.org".into()}else{String::new()} }
    }
    fn plan() -> LaunchPlan { LaunchPlan{java_executable:String::new(),working_directory:String::new(),main_class:String::new(),classpath_entries:vec![],modulepath_entries:vec![],main_module:String::new(),environment_allowlist:vec![],restrict_java_environment:false,jvm_args:vec![],game_args:vec!["--accessToken".into(),"wrong".into(),"--uuid=forged".into(),"--username".into(),"Other".into(),"--accessToken=forged".into()],command_preview:String::new(),deterministic_sha256:String::new()} }
    #[test] fn rejects_realm_confusion() {
        assert_eq!(identity(Some(&cred("msa"))).unwrap(),GameIdentity::Official);
        assert_eq!(identity(Some(&cred("mojang"))).unwrap(),GameIdentity::Yggdrasil);
        let mut c=cred("msa");c.auth_server_base_url="https://project.test".into();assert!(identity(Some(&c)).is_err());
        let mut c=cred("mojang");c.auth_server_base_url="http://evil.test".into();assert!(identity(Some(&c)).is_err());
        let mut c=cred("mojang");c.auth_server_base_url="https://user:pass@evil.test".into();assert!(identity(Some(&c)).is_err());
        let mut c=cred("mojang");c.user_type="legacy".into();assert!(identity(Some(&c)).is_err());
        let mut c=cred("msa");c.uuid="not-a-uuid".into();assert!(identity(Some(&c)).is_err());
    }
    #[test] fn repins_auth_arguments_without_duplicates() {
        let mut p=plan();pin_game_identity(&mut p,"1.21.8",Some(&cred("msa")),"ignored").unwrap();
        assert_eq!(p.game_args.iter().filter(|v|v.as_str()=="--accessToken").count(),1);
        assert!(!p.game_args.iter().any(|v|v.contains("forged")||v=="wrong"));
        assert!(p.game_args.windows(2).any(|x|x[0]=="--userType" && x[1]=="msa"));
        let mut p=plan();pin_game_identity(&mut p,"1.21.9",Some(&cred("msa")),"ignored").unwrap();
        assert!(!p.game_args.iter().any(|v|v=="--userType"));
        let mut p=plan();pin_game_identity(&mut p,"26.2",None,"OfflineUser").unwrap();
        assert!(!p.game_args.iter().any(|v|v=="--uuid"||v=="--userType"));
        assert!(p.game_args.windows(2).any(|x|x[0]=="--accessToken" && x[1]=="0"));
    }
    #[test] fn malformed_identity_args_fail_closed() {
        let mut p=plan();p.game_args.push("--uuid".into());
        assert!(pin_game_identity(&mut p,"1.20.1",Some(&cred("msa")),"Player").is_err());
    }
    #[test] fn cannot_inject_official_auth() {
        let mut p=plan();p.jvm_args.push("-javaagent:authlib-injector.jar=https://evil".into());
        assert!(pin_game_identity(&mut p,"1.20.1",Some(&cred("msa")),"x").is_err());
        assert!(pin_game_identity(&mut p,"1.20.1",None,"Player").is_err());
    }
}
