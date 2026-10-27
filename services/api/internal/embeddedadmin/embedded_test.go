package embeddedadmin

import (
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)
func TestEmbeddedAdmin(t *testing.T){
 h:=Handler()
 for _,path:=range []string{"/admin/","/admin/app.js","/admin/app.css"}{
  w:=httptest.NewRecorder();h.ServeHTTP(w,httptest.NewRequest("GET",path,nil))
  if w.Code!=200||w.Body.Len()==0{t.Fatalf("%s code=%d",path,w.Code)}
  if !strings.Contains(w.Header().Get("Content-Security-Policy"),"default-src 'none'"){t.Fatal("CSP missing")}
  if w.Header().Get("Cache-Control")!="no-store, max-age=0"{t.Fatal("cache enabled")}
 }
 for _,path:=range []string{"/admin/../../etc/passwd","/admin/secrets"}{w:=httptest.NewRecorder();h.ServeHTTP(w,httptest.NewRequest("GET",path,nil));if w.Code!=404{t.Fatalf("path %s leaked",path)}}
 w:=httptest.NewRecorder();h.ServeHTTP(w,httptest.NewRequest("POST","/admin/",nil));if w.Code!=http.StatusMethodNotAllowed{t.Fatal("unexpected write")}
}
