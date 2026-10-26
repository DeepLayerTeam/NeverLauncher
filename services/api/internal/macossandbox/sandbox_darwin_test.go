//go:build darwin

package macossandbox

import (
 "os"
 "path/filepath"
 "testing"
)

func TestUnsignedHelperAlwaysRejected(t *testing.T) {
 t.Setenv("NEVERLAUNCHER_MACOS_SANDBOX_HELPER", "")
 t.Setenv("NEVERLAUNCHER_MACOS_SANDBOX_TEAM_ID", "")
 if Available()==nil {t.Fatal("unsigned missing helper accepted")}
}
func TestWrongTeamIDRejected(t *testing.T) {
 t.Setenv("NEVERLAUNCHER_MACOS_SANDBOX_TEAM_ID", "NOT-A-TEAM")
 if _,err:=teamID();err==nil {t.Fatal("invalid team ID accepted")}
 t.Setenv("NEVERLAUNCHER_MACOS_SANDBOX_TEAM_ID", "ABCDEFG123")
 if _,err:=teamID();err!=nil {t.Fatal(err)}
}
func TestUntrustedHelperFileRejectedBeforeCodesign(t *testing.T) {
 dir:=t.TempDir()
 p:=filepath.Join(dir,"helper")
 if err:=os.WriteFile(p,[]byte("not-code"),0o666);err!=nil{t.Fatal(err)}
 if err:=os.Chmod(p,0o666);err!=nil{t.Fatal(err)}
 t.Setenv("NEVERLAUNCHER_MACOS_SANDBOX_HELPER",p)
 if _,err:=helperPath();err==nil {t.Fatal("group/world writable helper accepted")}
 if err:=os.Chmod(p,0o500);err!=nil{t.Fatal(err)}
 t.Setenv("NEVERLAUNCHER_MACOS_SANDBOX_TEAM_ID","ABCDEFG123")
 if Available()==nil{t.Fatal("unsigned executable accepted")}
}
