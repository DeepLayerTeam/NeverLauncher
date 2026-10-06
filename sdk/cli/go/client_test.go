package neverextensions
import("context";"errors";"testing")
func TestAppRejectsUnknownCommand(t *testing.T){app:=NewApp(Command{Name:"status",Run:func(context.Context,*Client,[]string)error{return nil}});err:=app.Run(context.Background(),[]string{"missing"});var exit *ExitError;if !errors.As(err,&exit)||exit.Code!=64{t.Fatalf("err=%v",err)}}
