// Живая приёмка опубликованного Go SDK против работающего промышленного API.
// Учётные данные передаются только через наследуемое закрытое окружение, никогда
// через argv.
package main

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "strings"
 "time"
 "unicode/utf8"

 neverapi "gitflic.ru/skif4er/launcher/sdk/api/go"
)
func required(key string) string { v:=os.Getenv(key); if v=="" { panic("missing live SDK configuration: "+key) }; return v }
func run() error {
 origin,token:=required("NL_GA_ORIGIN"),required("NL_GA_BEARER")
 jsonPath,textPath,binaryPath:=required("NL_GA_JSON_PATH"),required("NL_GA_TEXT_PATH"),required("NL_GA_BINARY_PATH")
 expected:=required("NL_GA_BINARY_SHA256")
 client,err:=neverapi.New(origin,token);if err!=nil{return err}
 ctx,cancel:=context.WithTimeout(context.Background(),4*time.Minute);defer cancel()
 if err=client.CheckCompatibility(ctx);err!=nil{return fmt.Errorf("live published API compatibility: %w",err)}
 var jsonBody map[string]any
 if err=client.Request(ctx,"GET",jsonPath,nil,nil,&jsonBody,"");err!=nil{return err}
 if len(jsonBody)==0{return errors.New("real API returned empty JSON")}
 // Проверяйте настоящие потоковые ответы, а не преобразование в JSON.
 var text strings.Builder
 n,err:=client.RequestStream(ctx,"GET",textPath,nil,nil,"",&text,1<<20,"")
 if err!=nil || n<10 || !utf8.ValidString(text.String()) || strings.ContainsRune(text.String(),'\x00') {
  return fmt.Errorf("real metrics/text SDK streaming failed: %v",err)
 }
 hash:=sha256.New()
 n,err=client.RequestStream(ctx,"GET",binaryPath,nil,nil,"",hash,1<<30,"")
 if err!=nil{return err};if n<8 || hex.EncodeToString(hash.Sum(nil))!=expected{return errors.New("live binary stream digest mismatch")}
 // Некорректные адреса должны отклоняться до передачи Bearer-токена.
 if _,err=client.RequestStream(ctx,"GET","https://untrusted.invalid",nil,nil,"",io.Discard,1024,"");err==nil{return errors.New("external origin not rejected")}
 fmt.Printf("PASS sdk=go checks=3 binaryBytes=%d binarySha256=%s\n",n,expected)
 return nil
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,"BLOCKED SDK Go: "+err.Error());os.Exit(2)}}
