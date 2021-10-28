# iauthcs.go
iauthcs is short for "It's All Under The Hood for Cybersource REST API". 
It puts everything under the hood and provides you with a powerful set of functions so you can easily "Do" payments.

Here's how you can integrate with Cybersource in the shortest time.

1. Obtain your Cybersource merchant credentials 

        merchant id, merchant key and merchant secret key

2. Download the package

        go get github.com/atkoroma/iauthcs

3. Import the package in your code
  
        import ("github.com/atkoroma/iauthcs")

4. Connect with the your merchant credentials you obtained in step 1. You must create a connection
first to avoid errors. DoGWConnect can be called at any time if you want to switch credentials

        cshost := "apitest.cybersource.com"
        merchantid := "enter_cybersource_merchant_id"
        merchantkey := "enter_cybersource_merchant_key"
        merchantsec := "enter_your_cybersource_secret_key"
 
        iauthcs.DoGWConnect(cshost, merchantid, merchantkey, merchantsec)
        
The package enable you to dynamically switch environment and endpoints. The default is "PAYMENT" 
The function is suitable when tokenizing a card, wherein you request a key first and then tokenize, at different endpoints.
It can also be used for regression by sending a request in test and then the same to the prod environment.
       
       iauthcs.DoSwitchTo("PAYMENT | KEY | TOKEN | REVERSAL | CAPTURE")

Once you've connected and decided what type of transaction you want to send (Payment authorization in this instance),
Do it with these parameters; "cardnumber, expiry_month, expiry_year, secret_code, order_amount".
An object of type PayResponse is returned when you invoke the command below;

      pay := iauthcs.DoPayAuthorization("4111111111111111","10","2028","195","10985.90")

how do I see the payment authorization response status

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

That's it, and the same goes for Authorization Reversals, Payment Captures and Card Tokenization. 
However, this version only contains payment authorization.

