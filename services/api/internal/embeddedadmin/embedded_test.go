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
  if w.Code!=200||w.Body.Len()==0{t.Fatalf("%s: код=%d",path,w.Code)}
  if !strings.Contains(w.Header().Get("Content-Security-Policy"),"default-src 'none'"){t.Fatal("Отсутствует политика безопасности содержимого CSP")}
  if w.Header().Get("Cache-Control")!="no-store, max-age=0"{t.Fatal("Кеш включён")}
 }
 for _,path:=range []string{"/admin/../../etc/passwd","/admin/secrets"}{w:=httptest.NewRecorder();h.ServeHTTP(w,httptest.NewRequest("GET",path,nil));if w.Code!=404{t.Fatalf("Произошла утечка пути %s",path)}}
 w:=httptest.NewRecorder();h.ServeHTTP(w,httptest.NewRequest("POST","/admin/",nil));if w.Code!=http.StatusMethodNotAllowed{t.Fatal("Неожиданная операция записи")}
}
