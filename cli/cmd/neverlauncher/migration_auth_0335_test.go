package main

import (
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestMigrationAuthCLITransport0335(t *testing.T){
 source:=filepath.Join(t.TempDir(),"source.zip")
 if e:=os.WriteFile(source,[]byte("PK__sample"),0600);e!=nil{t.Fatal(e)}
 called:=0
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  called++
  if r.Method!="POST"||r.Header.Get("Authorization")!="Bearer test-token"||r.Header.Get("X-Gravit-Password-Format")!="sha256-hex"||r.Header.Get("X-Migration-Import-Confirm")!="run-xyz" {t.Errorf("incorrect auth import headers: %+v",r.Header)}
  if r.ContentLength!=10 {t.Errorf("source upload not streaming with known length: %d",r.ContentLength)}
  w.Header().Set("Content-Type","application/json")
  _=json.NewEncoder(w).Encode(map[string]any{"data":map[string]any{"runId":"run-xyz","imported":1}})
 }))
 defer srv.Close()
 out:=filepath.Join(t.TempDir(),"private-report.json")
 if e:=postMigrationAuth0335(srv.URL+"/import","test-token",source,"sha256-hex","run-xyz",out,true);e!=nil{t.Fatal(e)}
 if called!=1{t.Fatalf("expected one request, got %d",called)}
 stat,e:=os.Stat(out);if e!=nil{t.Fatal(e)}
 if stat.Mode().Perm()!=0600{t.Fatalf("report exposed: %v",stat.Mode())}
 data,e:=os.ReadFile(out);if e!=nil||!strings.Contains(string(data),`"imported": 1`){t.Fatalf("missing result: %s %v",data,e)}
 if e:=postMigrationAuth0335(srv.URL+"/import","test-token",source,"sha256-hex","run-xyz",out,true);!os.IsExist(e){t.Fatalf("report overwrite allowed: %v",e)}
 if e:=postMigrationAuth0335("http://example.com/credentials/import","test-token",source,"sha256-hex","run-xyz","",true);e==nil{t.Fatal("credential transmission over insecure public HTTP accepted")}
}
