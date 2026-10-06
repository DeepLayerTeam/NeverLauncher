package neverextensions

import (
  "context"
  "net/http"
  "testing"
  "time"
)

func TestCallbackServerRequiresToken(t *testing.T){
  c:=New(HostEnvironment{CallbackToken:"secret"})
  s,err:=c.StartCallbackServer(func(context.Context,EventEnvelope)error{return nil},nil);if err!=nil{t.Fatal(err)}
  defer s.Close(context.Background())
  req,_:=http.NewRequest(http.MethodPost,s.URL+"/v1/events",nil)
  resp,err:=http.DefaultClient.Do(req);if err!=nil{t.Fatal(err)};defer resp.Body.Close();if resp.StatusCode!=http.StatusUnauthorized{t.Fatalf("status=%d",resp.StatusCode)}
}
func TestEnvironmentRejectsIncompleteHost(t *testing.T){
  t.Setenv("NEVERLAUNCHER_EXTENSION_HOST_URL","");t.Setenv("NEVERLAUNCHER_EXTENSION_HOST_TOKEN","");t.Setenv("NEVERLAUNCHER_EXTENSION_ID","");t.Setenv("NEVERLAUNCHER_EXTENSION_INSTANCE_ID","")
  if _,err:=Environment();err==nil{t.Fatal("expected incomplete host environment error")}
}
func TestNewUsesBoundedHTTPClient(t *testing.T){c:=New(HostEnvironment{});if c.http.Timeout!=10*time.Second{t.Fatalf("timeout=%s",c.http.Timeout)}}
