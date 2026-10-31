package gravitcredentials

import (
 "archive/zip"
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "strings"
 "testing"

 inv "gitflic.ru/skif4er/launcher/services/api/internal/gravitinventory"
)

func sourceFixture335(t *testing.T, entries map[string]string)([]byte,inv.Inventory){
 t.Helper();var buf bytes.Buffer;z:=zip.NewWriter(&buf)
 for name,value:=range entries{w,e:=z.Create(name);if e!=nil{t.Fatal(e)};if _,e=w.Write([]byte(value));e!=nil{t.Fatal(e)}}
 if e:=z.Close();e!=nil{t.Fatal(e)}
 b:=buf.Bytes();digest:=sha256.Sum256(b)
 snapshot,e:=inv.Inspect(context.Background(),bytes.NewReader(b),int64(len(b)),hex.EncodeToString(digest[:]));if e!=nil{t.Fatal(e)}
 return b,snapshot
}
func TestFileAuthCredentialExtraction335(t *testing.T){
 original:=strings.Repeat("a",64)
 src,snapshot:=sourceFixture335(t,map[string]string{
  "modules-config/FileAuthSystem/Database.json":`{"11111111-2222-4333-8444-555555555555":{"username":"Player335","uuid":"11111111-2222-4333-8444-555555555555","password":"`+original+`"}}`,
  "modules-config/FileAuthSystem/Sessions.json":`{"session":"DO_NOT_COPY"}`,
 })
 entries,e:=Extract(context.Background(),bytes.NewReader(src),int64(len(src)),snapshot,"sha256-hex")
 if e!=nil{t.Fatal(e)}
 if len(entries)!=1||entries[0].PasswordHash==""||entries[0].Algorithm!="sha256-hex"{t.Fatalf("unexpected entries: %+v",entries)}
 raw,e:=json.Marshal(entries);if e!=nil{t.Fatal(e)}
 if bytes.Contains(raw,[]byte(original))||bytes.Contains(raw,[]byte("$never-gravit"))||bytes.Contains(raw,[]byte("DO_NOT_COPY")){t.Fatal("hash leaked in report")}
 if _,e=Extract(context.Background(),bytes.NewReader(src),int64(len(src)),snapshot,"");e==nil{t.Fatal("accepted unconfigured algorithm")}
 changed:=snapshot;changed.SourceSHA256=strings.Repeat("0",64)
 if _,e=Extract(context.Background(),bytes.NewReader(src),int64(len(src)),changed,"sha256-hex");e==nil{t.Fatal("accepted changed source")}
}
func TestSQLCredentialsSelectiveManual335(t *testing.T){
 hash:=strings.Repeat("b",64)
 src,snapshot:=sourceFixture335(t,map[string]string{"sql-export/users.csv": "id,username,uuid,password_hash,password_format\n7,PlayerOne,11111111-2222-4333-8444-555555555555,"+hash+",sha256-hex\n8,PlayerTwo,aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee,LEGACY_CUSTOM,unknown-hash\n"})
 entries,e:=Extract(context.Background(),bytes.NewReader(src),int64(len(src)),snapshot,"");if e!=nil{t.Fatal(e)}
 if len(entries)!=2||entries[0].State!="importable"||entries[1].State!="manual_reset"||entries[1].PasswordHash!=""{t.Fatalf("unexpected SQL selection %+v",entries)}
 invalid:=strings.ReplaceAll(string(src),"password_hash","invalid")
 _=invalid // A mutated ZIP would fail the inventory check before parsing.
 _,e=parseSQL([]byte("id,username,uuid,password_hash,password_format\n7,Bob,11111111-2222-4333-8444-555555555555,nothex,sha256-hex\n"),"sql-export/users.csv")
 if e==nil{t.Fatal("accepted invalid claimed password hash")}
}
func TestDecisionFingerprint335(t *testing.T){
 if SourceFingerprint("a","b","sha256-hex")==SourceFingerprint("a","b","md5-hex"){t.Fatal("algorithm not bound")}
}
