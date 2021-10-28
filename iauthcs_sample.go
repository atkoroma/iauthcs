package main

import (
        "fmt"
        "atkoroma/iauthcs"
)


func main() {

        fmt.Println("\tiauthcs...demo\n")
        // client connection parameters
        cshost := "apitest.cybersource.com"
        merchantid := "enter cybersource merchant id"
        merchantkey := "enter cybersource merchant key"
        merchantsec := "enter your cybersource secret key"

        // connect to gateway with iauthcs
        iauthcs.DoGWConnect(cshost, merchantid, merchantkey, merchantsec)
        
        // switch environment to payment endpoint
        iauthcs.DoSwitchTo("PAYMENT")
        
        //make a payment authorization request and store the response in pay
        pay := iauthcs.DoPayAuthorization("4111111111111111","10","2028","195","10985.90")

        //display information in pay
        fmt.Println("\t\nPayment: " + pay.ResponseStatus + "\n")
        fmt.Printf("\t\nPload: %+v\n", pay)
}
