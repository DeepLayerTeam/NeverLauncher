package gravitidentity

import (
 "archive/zip"
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "strings"
 "testing"

 inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
)
func archive334(t *testing.T, files map[string]string) ([]byte,inv.Inventory) {
 t.Helper();var buf bytes.Buffer;w:=zip.NewWriter(&buf)
 for name,value:=range files {f,e:=w.Create(name);if e!=nil{t.Fatal(e)};if _,e=f.Write([]byte(value));e!=nil{t.Fatal(e)}}
 if e:=w.Close();e!=nil{t.Fatal(e)}
 bytes:=buf.Bytes();hash:=sha256.Sum256(bytes);v,e:=inv.Inspect(context.Background(),strings.NewReader(string(bytes)),int64(len(bytes)),hex.EncodeToString(hash[:]));if e!=nil{t.Fatal(e)}
 return bytes,v
}
func TestExtractFileAuth334(t *testing.T) {
 src,snapshot:=archive334(t,map[string]string{
  "modules-config/FileAuthSystem/Database.json":`{"11111111-2222-4333-8444-555555555555":{"username":"Alice_01","uuid":"11111111-2222-4333-8444-555555555555","password":"should-appear","permissions":{"roles":["ADMIN"]}}}`,
  "modules-config/FileAuthSystem/Sessions.json":`{"accessToken":"SECRET"}`,
 })
 result,e:=Extract(context.Background(),bytes.NewReader(src),int64(len(src)),snapshot);if e!=nil{t.Fatal(e)}
 if len(result)!=1 || result[0].Username!="Alice_01" || result[0].Provider!="fileauth" {t.Fatalf("unexpected accounts %+v",result)}
 for _,a:=range result{if strings.Contains(a.Username,"SECRET") || strings.Contains(a.SourceID,"password"){t.Fatal("secret persisted")}}
 stale:=snapshot;stale.ManifestSHA256=strings.Repeat("f",64)
 if _,e=Extract(context.Background(),bytes.NewReader(src),int64(len(src)),stale);e==nil{t.Fatal("changed manifest accepted")}
}
func TestFileAuthRefusesKeyDisagreement334(t *testing.T) {
 _,e:=parseFileAuth([]byte(`{"11111111-2222-4333-8444-555555555555":{"username":"Alice","uuid":"99999999-2222-4333-8444-555555555555"}}`),"/FileAuthSystem/Database.json")
 if e==nil{t.Fatal("embedded UUID mismatch accepted")}
 _,e=parseFileAuth([]byte(`{"11111111-2222-4333-8444-555555555555":{"username":"Alice"},"11111111-2222-4333-8444-555555555555":{"username":"Bob"}}`),"FileAuthSystem/Database.json")
 if e==nil{t.Fatal("duplicate JSON map key accepted")}
}
func TestSQLCSVAndCrossSourceCollision334(t *testing.T) {
 src,snapshot:=archive334(t,map[string]string{
  "sql-export/users.csv":"id,username,uuid,password,accessToken\n17,Bob,aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee,SECRET,SECRET\n",
  "configs/FileAuthSystem/Database.json":`{"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee":{"username":"Bob"}}`,
 })
 accounts,e:=Extract(context.Background(),bytes.NewReader(src),int64(len(src)),snapshot);if e!=nil{t.Fatal(e)}
 if len(accounts)!=2{t.Fatalf("got %d",len(accounts))}
 mapped,summary:=Reconcile(accounts,nil);if summary["blocked"]!=2{t.Fatalf("duplicate UUID not blocked: %+v %+v",summary,mapped)}
}
func TestReconcileUUIDCollisionAndCaseFolding334(t *testing.T) {
 alice:=Account{Provider:"fileauth",SourceID:"src-a",Username:"Alice",UUID:"11111111-2222-4333-8444-555555555555"}
 bob:=Account{Provider:"sql",SourceID:"9",Username:"Bob",UUID:"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}
 targets:=[]Target{{UserID:"target-a",Username:"Alice",UUID:alice.UUID},{UserID:"target-a",Username:"Alice",UUID:alice.UUID,Source:"official_link"},{UserID:"target-b",Username:"Bob",UUID:"99999999-bbbb-4ccc-8ddd-eeeeeeeeeeee"}}
 rows,sum:=Reconcile([]Account{alice,bob},targets)
 if sum["matched"]!=1 || sum["blocked"]!=1 || rows[0].TargetUserID!="target-a" {t.Fatalf("unexpected mapping %+v %+v",rows,sum)}
 rows,sum=Reconcile([]Account{alice},[]Target{{UserID:"target-x",Username:"Alice",UUID:"99999999-2222-4333-8444-555555555555"}})
 if sum["blocked"]!=1 {t.Fatal("same-name different UUID accepted")}
 rows,sum=Reconcile([]Account{alice, {Provider:"sql",SourceID:"10",Username:"alice",UUID:"12345678-2222-4333-8444-555555555555"}},nil)
 if sum["blocked"]!=2 {t.Fatalf("case-insensitive collision accepted: %+v",rows)}
 _,sum=Reconcile([]Account{alice},nil);if sum["pending_import"]!=1{t.Fatal("unknown UUID was auto-linked")}
}
func TestExtractRejectsUnrecognizedAndInvalid334(t *testing.T) {
 src,report:=archive334(t,map[string]string{"Sessions.json":`{"accessToken":"secret"}`})
 if _,e:=Extract(context.Background(),bytes.NewReader(src),int64(len(src)),report);e==nil{t.Fatal("sessions accepted as users")}
 src,report=archive334(t,map[string]string{"sql-export/users.csv":"username,uuid\nAlice,11111111-2222-4333-8444-555555555555\n"})
 if _,e:=Extract(context.Background(),bytes.NewReader(src),int64(len(src)),report);e==nil{t.Fatal("SQL CSV without stable id accepted")}
}
