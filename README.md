# iAuth-CS
iAuth-CS is a Golang payment library for the Cybersource REST API. It exposes capabilities for "payment authorization", "authorization reversal", "payment capture" & "card tokenization". They are available through a simple set of easy-to-use functions, that could get you accepting card payments sooner than anticipated. 

If you're a Golang developer looking for ready-to-integrate payment library...then make ````iauthcs```` your friend.

```iauthcs``` is short for ***i***t's ***a***ll ***u***nder ***t***he ***h***ood for [Cybersource REST API](https://developer.cybersource.com/api-reference-assets/index.html). 
Cybersource provides REST APIs to integrate with its payment gateway services. The integration can be difficult-ish to accomplish from scratch.
Going through the tedious coding process, I decided to provide a much simpler way that take the borden off, of you the Go developer.

Don't the intimidated by the long literature, there are only four(4) functions to use. The rest are requests and response outputs.
This has to be the simplest payment gateway integration out there, it will enable you to accept payments is minutes...

***It's all under the hood*** means you will ***Not*** have to...
- Build payloads
- Sign your data
- Decode, encode and encrypt your data
- Message digest your payload and a few more...

## Functions() ##
For the simplicity sakes, ```iauthcs``` exposes a function per payment transaction type as listed below.

- DoPaymentAuth() - sends a payment authorization (with card details) and returns the gateway response 

- DoPaymentCapture() - sends a payment capture and returns the gateway response

- DoAuthReversal() - sends a payment authorization reversal request and returns the gateway response

- DoCardTokenize() - generates pubkey, encrypts card, requests a token and returns the gateway response


iAuth-CS allows the developer to truely focus on the application rather than back-end heavy weight calls. 

_That's how we want you the Go developer to Do payments_

# Getting started #
**Here's how you can integrate with Cybersource in the shortest time.**

##### 1. Create a [Cybersource merchant account](https://ebc2.cybersource.com/ebc2/registration/external) which will provide you with the following; #####

        merchant-id, merchant-key & merchant-secret-key

##### 2. Download ```iauthcs.go``` package from github #####

        go get github.com/atkoroma/iauthcs

##### 3. Import the package in your golang code #####
  
        import ("github.com/atkoroma/iauthcs")

# Usage #

## Gateway connect ##
A gateway connect call is required in order to pass your merchant credentials for later internal use by the library. 

        cshost := "apitest.cybersource.com"
        merchantid := "enter_cybersource_assigned_merchant_id"
        merchantkey := "enter_cybersource_assinged_merchant_key"
        merchantsec := "enter_your_cybersource_assigned_secret_key"
 
        iauthcs.DoGWConnect(cshost, merchantid, merchantkey, merchantsec)
        
## Process a payment ##
A payment authorization request:

        p := iauthcs.DoPayAuthorization(card_number, expiry_month, expiry_year, secret_code, order_amount)

Payment authorization response:

Response is a data struct of type PayResponse, where "p" above, will contain the following fields;

        PayResponse {
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

See [iauthcs_sample.go](https://github.com/atkoroma/iauthcs/blob/iauthcs/iauthcs_sample.go) for a working sample code

## Process a reversal ##
An authorization reversal transaction request:

      r := iauthcs.DoAuthReversal(p.AuthReversalHref, p.OrderAmt)

An authorization reversal response:

Response is a data struct of type RevResponse, where "r" above, will contain the following fields;

        RevResponse  {
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
                ErrorMessage string
        }


See [iauthcs_sample.go](https://github.com/atkoroma/iauthcs/blob/iauthcs/iauthcs_sample.go) for a working sample code

## Process a capture ##
A payment capture transaction request:

      c := iauthcs.DoPaymentCapture(p.CaptureHref, p.OrderAmt)

A payment capture response:

Response is a data struct of type CapResponse, where "c" above, will contain the following fields;


        CapResponse {
                VoidMeth string
                VoidHref string
                SelfMeth string
                SelfHref string
                ClientRefId string
                TransactId string
                OrderAmt string
                OrderCur string
                ReconciliationId string
                ResponseStatus string
                SubmitTimeUtc string
                ErrorMessage string
        }

See [iauthcs_sample.go](https://github.com/atkoroma/iauthcs/blob/iauthcs/iauthcs_sample.go) for a working sample code


## Card tokenization ##
A tokenize card transaction requires the parameters: *** ***.

      t := iauthcs.DoCardTokenize()

A payment capture response:

Response is a data struct of type ToxResponse, where "t" above, will contain the following fields;

        ToxResponse {
             . . . .
        }

_Details on card tokenization coming soon or contact me to share your interest._

## Key features under the hood... ##
The prominent features of the library are;

#### Zero integration code ####

The developer do not write any gateway integration code. If you noticed, the functions are transactional. It's basically a connect-and-transact concept.

#### Dynamic context switching ####

```iauthcs``` is context aware and it supports service environment and service endpoint contexts. 
This means you can you perform a transaction, then switch to another environment and/or endpoint, and perform the same or different
transaction without break. It is useful in many use cases e.g regression testing and failover handling. I used it to implement the card tokenization
where, you first generate a key with data received from the key endpoint, to encrypt the card data for tokenization request to the token endpoint.
But don't worry about such stuff, it's all under the hood :)

Dynamic context switching is implemented by two functions for environment and endpoint respectively 
```
DoGWConnect(): switch environment context from test to prod and vice-visa
DoSwitchTo(): switches service endpoint context between "PAYMENT|REVERSAL|CAPTURE|TOKEN"
```
#### Parameterization ####

The behavior of the library can be modified with the following parameter;
```
GWConfig {
        DumpPayload bool        //dumps the http request and response. great for debugging
        AutoGenTransactId bool  //auto generates a unique transaction id for each payment auth
        LogToFile string        //logs all transactions to file specified
}
```



## Technical support information ##

| Description   | Service | Based on  |
| ------------- | ------------- |---------------|
| Authorization  | Payments  |       v2         |
| Reversal  | Payments  |       v2         |
| Capture  | Payments        |       v2         |
| Flex  | Token Management   |       v1         |
| Message authentication  |  Payments  |       HmacSHA256         |
| Message digest  | Payments   |       SHA256         |
| Card encryption  | Token management   |       rsa.EncryptOAEP   |



***Go Do payments and enjoy it!!***

