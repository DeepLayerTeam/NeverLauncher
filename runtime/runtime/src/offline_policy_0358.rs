// 0.35.8. The owner-signed offline profile authorizes only local play.
// In particular, a signed launch argument must not sneak a server auto-join
// into a launch in which the UI deliberately disabled auto-enter.
use crate::LaunchPlan;

pub fn reject_offline_server_autojoin_0358(plan: &LaunchPlan) -> Result<(), String> {
    for arg in &plan.game_args {
        let flag = arg.split('=').next().unwrap_or(arg).to_ascii_lowercase();
        if ["--server", "--quickplaymultiplayer", "--quickplayrealms"].contains(&flag.as_str()) {
            return Err("offline launch denied: game arguments request a network server auto-join".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan(args: &[&str]) -> LaunchPlan {
        LaunchPlan { java_executable:String::new(),working_directory:String::new(),
            main_class:String::new(),classpath_entries:vec![],modulepath_entries:vec![],
            main_module:String::new(),environment_allowlist:vec![],restrict_java_environment:false,
            jvm_args:vec![],game_args:args.iter().map(|v|v.to_string()).collect(),
            command_preview:String::new(),deterministic_sha256:String::new() }
    }
    #[test]
    fn local_single_player_allowed_and_server_autojoin_forbidden() {
        assert!(reject_offline_server_autojoin_0358(&plan(&["--username","OfflineUser","--accessToken","0","--quickPlaySingleplayer","World"])).is_ok());
        for args in [vec!["--server","mc.example.org"],vec!["--server=mc.example.org"],
                     vec!["--quickPlayMultiplayer","mc.example.org:25565"],vec!["--quickplayrealms=123"]] {
            assert!(reject_offline_server_autojoin_0358(&plan(&args)).is_err());
        }
    }
}
