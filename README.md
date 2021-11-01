# iauthcs.go
iauthcs is short for "It's All Under The Hood for Cybersource REST API". 
It puts everything under the hood by providing a single functioin per payment transaction type...namely;
``` 
DoPaymentAuth() - for payment authorization 
DoPaymentCapture() - for payment capture
DoAuthReversal() - for payment authorization reversal
DoCardTokenize() - for card tokenization
```
With iauthcs, the developer can truely focus on the front-end and not the back-end heavy lifting. 

That's how iauthcs feels you should "Do" payments.

**Here's how you can integrate with Cybersource in the shortest time.**

##### 1. Obtain your Cybersource merchant credentials. They will assign the below to your merchant account #####

        merchant id, merchant key and merchant secret key

##### 2. Download "iauthcs" package #####

        go get github.com/atkoroma/iauthcs

##### 3. Import the package in your golang code #####
  
        import ("github.com/atkoroma/iauthcs")

##### 4. Connect with the your merchant credentials you obtained in step 1. You must create a connection first to avoid errors. Use ```DoGWConnect``` to create your gateway connection. You can switch credentials dynamically by calling DoGWConnect #####

        cshost := "apitest.cybersource.com"
        merchantid := "enter_cybersource_merchant_id"
        merchantkey := "enter_cybersource_merchant_key"
        merchantsec := "enter_your_cybersource_secret_key"
 
        iauthcs.DoGWConnect(cshost, merchantid, merchantkey, merchantsec) error { }
        
In addition to dynamic credential switching, it also enables you to dynamically switch environments/endpoints. The default endpoint is "PAYMENT". 
````DoSwitchTo```` simplifies a card tokenization, wherein the key and tokenize requests are different endpoints, and both to be handled to complete the process.

It can also be useful in regression, by sending a request in test environment and then the same to the prod environment.
       
##### It is achieved by passingJust pass the payment type to switch it (default="PAYMENT"). There is no need to DoSwitchTo for payment authorization #####

       iauthcs.DoSwitchTo("PAYMENT | KEY | TOKEN | REVERSAL | CAPTURE") { }

Once you've connected and decided what type of transaction you want to send (Payment authorization in this instance),
"Do" so with these parameters; "cardnumber, expiry_month, expiry_year, secret_code, order_amount".
An object of type PayResponse is returned when you invoke the command below;

      pay := iauthcs.DoPayAuthorization("4111111111111111","10","2028","195","985.90") PayResponse { }

##### How do I see the payment authorization response status #####

      pay.ResponseStatus

The authorization response (e.g "pay" above) contains the following fields;

        type PayResponse struct {
                AuthReversalMethod string
                AuthReversalHref string
                SelfMeth string
                SelfHref string
                CaptureMeth string
                CaptureHref string
                ClientRefId string
                TransactId string
                Orderamt string
                OrderCur string
                CardType string
                TokenType string
                PointOfSaleId string
                ProcessorApprovalCode string
                ProcessorVerificationRCode string
                ProcessorNetworkTransactionId string
                ProcessorTransactionId string
                ProcessorResponseCode string
                ProcessorAvsCode string
                ProcessorAvsCodeRaw string
                ReconciliationId string
                ResponseStatus string
                SubmitTimeUtc string
                ErrorMessage string
        }

See the sample_iauthcs.go for a working examples.

That's it, and the same goes for Authorization Reversals, Payment Captures and Card Tokenization. 
However, this version only contains payment authorization.

