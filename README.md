# iauthcs.go
How "Do" you do ***payment authorization, authorization reversal, payment capture and card tokenization*** (payments) on the Cybersource gateway using golang? 
You make ````iauthcs```` your friend.

```iauthcs``` is short for ***i***t's ***a***ll ***u***nder ***t***he ***h***ood for [Cybersource REST API](https://developer.cybersource.com/api-reference-assets/index.html). 
Cybersource provides REST APIs to integrate with its payment gateway services. The integration can be difficult-ish to accomplish from scratch.
Going through the tidious coding process, I decided to provide a much simpler way that take the borden off, of you the Go developer.

Don't the intimidated by the long literature, there are only four(4) functions to use. The rest is explaining what is under the hood.
This has to be the simplest payment gateway integration out there, it will enable you to accept payments is minutes...

***It's all under the hood*** means you will ***NOT*** have to...
- build payloads
- Sign your data
- Decode, encode and encrypt your data
- Message digest your payload and a few more...

For simplicity, it exposes one function per payment transaction type as listed below.

#### Functions ####

``` 
DoPaymentAuth() - sends a payment authorization and returns the gateway response 
DoPaymentCapture() - sends a payment capture and returns the gateway response
DoAuthReversal() - sends a payment authorization reversal request and returns the gateway response
DoCardTokenize() - retrieve a key, encrypts the card, request to tokenize and returns the gateway response
```
````iauthcs```` allows the developer to truely focus on the application rather than back-end heavy weight-lifting. 

That's how ````iauthcs```` wants you the Go developer to "Do" payments.

## Usage ##
**Here's how you can integrate with Cybersource in the shortest time.**

##### 1. Create a [Cybersource merchant account](https://ebc2.cybersource.com/ebc2/registration/external) that will provide you with the following; #####

        merchant id, merchant key and merchant secret key

##### 2. Download "iauthcs" package #####

        go get github.com/atkoroma/iauthcs

##### 3. Import the package in your golang code #####
  
        import ("github.com/atkoroma/iauthcs")

##### 4. Connect with the your merchant credentials you obtained in step 1. ####
You must create a connection first to avoid errors. Use ```DoGWConnect``` to create your gateway connection. 
You can dynamically switch connection between environment using ```DoGWConnect``` 

        cshost := "apitest.cybersource.com"
        merchantid := "enter_cybersource_assigned_merchant_id"
        merchantkey := "enter_cybersource_assinged_merchant_key"
        merchantsec := "enter_your_cybersource_assigned_secret_key"
 
        iauthcs.DoGWConnect(cshost, merchantid, merchantkey, merchantsec) error { }
        
## Process a payment ##
A payment authorization transaction requires the parameters: ***cardnumber, expiry_month, expiry_year, secret_code, order_amount***.

      p := iauthcs.DoPayAuthorization("4111111111111111","10","2028","195","985.90")

```DoPayAuthorization``` will return an authorization response of type PayResponse where "p" above, will contain the following fields;

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

See file ````iauthcs_sample.go```` for a working example

## Process a reversal ##
An authorization reversal transaction requires the parameters: ***href_from_auth, order_amount***.

      r := iauthcs.DoAuthReversal(p.AuthReversalHref, p.OrderAmt)

```DoAuthReversal``` will return an authorization reversal response of type RebResponse where "r" above, will contain the following fields;

        type RevResponse struct {
                RevSelfMeth string
                RevSelfHref string
                ClientRefId string
                TransactId string
                OrderCur string
                ProcessorResponseCode string
                ReversedAmount string
                ReversedCur string
                ResponseStatus string
                SubmitTimeUtc string
                ErrorMsg string
        }


See file ````iauthcs_sample.go```` for a working example

## Process a capture ##
A payment capture transaction requires the parameters: ***href_from_auth, order_amount***.

      c := iauthcs.DoPaymentCapture(p.CaptureHref, p.OrderAmt)

```DoPaymentCapture``` will return an payment capture response of type CapResponse where "c" above, will contain the following fields;

        type CapResponse struct {
                RevSelfMeth string
                RevSelfHref string
                ClientRefId string
                TransactId string
                OrderCur string
                ProcessorResponseCode string
                ReversedAmount string
                ReversedCur string
                ResponseStatus string
                SubmitTimeUtc string
                ErrorMsg string
        }


See file ````iauthcs_sample.go```` for a working example


## Card tokenization ##
A tokenize card transaction requires the parameters: *** ***.

      t := iauthcs.DoCardTokenize()

```DoCardTokenize``` will return an payment capture response of type ToxResponse where "t" above, will contain the following fields;

        type ToxResponse struct {
             . . . .
        }


Details on card tokenization coming soon.

## Technical support information ##

| Description   | Service | Based on version  |
| ------------- | ------------- |---------------|
| Authorization  | Payments  |       v2         |
| Reversal  | Payments  |       v2         |
| Capture  | Payments        |       v2         |
| Flex  | Token Management   |       v1         |

***Go Do payments and enjoy it***
