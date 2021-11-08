//////////////////////////////////////////////////////////////
//iauthcs.go ////////////////////////////////////////////////
//(c)2021 koroma_consulting ////////////////////////////////
//author: alie@koroma.co.za(alie.tormusa.koroma) //////////
//////////////////////////////////////////////////////////

package iauthcs

import (
	//"os"
	//"io"
	"fmt"
	//"log"
	"time"
	"bytes"
	"errors"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	//"encoding/pem"
	"crypto/sha256"
	//"crypto/cipher"
	"crypto/rand"
	//"crypto/aes" 
	//"crypto/rsa" 
	"crypto/hmac"
	//"crypto/x509" 
	"strings"
	"strconv"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
)

////////////////////////////////////////////////////
////////////////////////////////////////////////////
// PaymentRequest_Struct
////////////////////////////////////////////////////
///////////////////////////////////////////////////
type ClientReferenceInformation struct {
   Code string `json:"code"`
}

type ProcessingInformation struct {
   CommerceIndicator string `json:"commerceIndicator"`
}

type Card struct {
   Number string        `json:"number"`
   ExpirationMonth string  `json:"expirationMonth"`
   ExpirationYear string	`json:"expirationYear"`
   SecurityCode string  `json:"securityCode"`
}

type PaymentInformation struct {
  Card Card     `json:"card"`
}

type AmountDetails struct {
  TotalAmount string   `json:"totalAmount"`
  Currency string       `json:"currency"`
}

type BillTo struct {
   FirstName string `json:"firstName"`
   LastName string `json:"lastName"`
   Company string       `json:"company"`
   Address1 string      `json:"address1"`
   Address2 string      `json:"address2"`
   Locality string      `json:"locality"`
   AdministrativeArea string    `json:"administrativeArea"`
   PostalCode string    `json:"postalCode"`
   Country string       `json:"country"`
   Email string         `json:"email"`
   PhoneNumber string   `json:"phoneNumber"`
}

type OrderInformation struct {
   AmountDetails AmountDetails `json:"amountDetails"`
   BillTo BillTo `json:"billTo"`
}

type Payment struct {
   ClientReferenceInformation ClientReferenceInformation `json:"clientReferenceInformation"`
   ProcessingInformation ProcessingInformation `json:"processingInformation"`
   //AggregatorInformation AggregatorInformation `json:"aggregatorInformation"`
   PaymentInformation PaymentInformation `json:"paymentInformation"`
   OrderInformation OrderInformation `json:"orderInformation"`
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
//// ///////////////  PaymentAuthResponse_Struct	///////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
// create struct types for unmarshal'ling the payment response

//_links_information
type AuthReversal struct {
	Method string `json:"method"`
	Href string `json:"href"`
}
type Self struct {
	Method string `json:"method"`
	Href string `json:"href"`
}
type Capture struct {
	Method string `json:"method"`
	Href string `json:"href"`
}
type Links struct {
	AuthReversal AuthReversal `json:"authReversal"`
	Self Self `json:"self"`
	Capture Capture `json:"capture"`
}

//client_reference_information    
//type ClientResponseReferenceInformation struct {
//   Code string `json:"code"`
//}

//the_id_information
type RespId struct {
   RespId string `json:"id"`
}

//the_order_informatioin
type RespAmountDetails struct {
  AuthorizedAmount string   `json:"authorizedAmount"`
  Currency string       `json:"currency"`
}
type RespOrderInformation struct {
   AmountDetails RespAmountDetails `json:"amountDetails"`
}

//payment_account_information
type RespCard struct {
   Type string        `json:"type"`
}
type PaymentAccountInformation struct {
  RespCard RespCard     `json:"card"`
}

//payment_information
type TokenizedCard struct {
   Type string        `json:"type"`
}
type RespPaymentInformation struct {
  TokenizedCard TokenizedCard     `json:"tokenizedCard"`
}

//point_of_sale
type PointOfSaleInformation struct {
   TerminalId string `json:"terminalId"`
}

//processor_information
type AVS struct {
   Code string `json:"code"`
   CodeRaw string `json:"codeRaw"`
}
//type ResponseCode struct {
//   CodeResponded string `json:"responseCode"`
//}
type CardVerification struct {
	Resultcode string `json:"resultcode"`
}

type ProcessorInformation struct {
	ApprovalCode string `json:"approvalCode"`
    	CardVerification CardVerification `json:"cardVerification"`
	NetworkTransactionId string `json:"networkTransactionId"`
	TransactionId string `json:"transactionId"`
	ResponseCode string `json:"responseCode"`
	Avs AVS `json:"avs"`
}

type ErrorInformation struct {
       Reason  string `json:"reason"`
       Message string `json:"message"`
} 

type PaymentAuthResponse struct {
   Links Links `json:"_links"`
   ClientReferenceInformation ClientReferenceInformation `json:"clientReferenceInformation"`
   RespId string `json:"id"`
   RespOrderInformation RespOrderInformation `json:"orderInformation"`
   PaymentAccountInformation PaymentAccountInformation `json:"paymentAccountInformation"`
   RespPaymentInformation RespPaymentInformation `json:"paymentInformation"`
   PointOfSaleInformation PointOfSaleInformation `json:"pointOfSaleInformation"`
   ProcessorInformation ProcessorInformation `json:"processorInformation"`
   ReconciliationId string `json:"reconciliationId"`
   RespStatus string `json:"status"`
   SubmitTimeUtc string `json:"submitTimeUtc"`
   ErrorInformation ErrorInformation `json:"errorInformation"`
}

/////////////////////////////////////////////////////////////////
// PayResponse (user response data structure) //////////////////
///Maps the payment authorization response for user access ////
//////////////////////////////////////////////////////////////
        type PayResponse struct {
                //extract the response values
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

//////////////END////////////////////////////////////////////


////////////////////////////////////////////////////////////////
// TOKEN.KEY.REQUEST.STRUCT////////////////////////////////////
//TokenKeyRequest-Structs/////////////////////////////////////
/////////////////////////////////////////////////////////////
type TokenKeyRequest struct {
    EncryptionType	string	`json:"encryptionType"`
    TargetOrigin	string `json:"targetOrigin"`
}

//Token key response structs
type Der struct {
	Format    string `json:"format"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`	
}

type Jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type TokenKeyResponse struct {
	KeyID string `json:"keyId"`
	Der	Der `json:"der"`
	Jwk	Jwk `json:"jwk"`
}

//////////////////////////////////////////
//Tokenize card request+response structs//
//////////////////////////////////////////
type TokenCardDetails struct {
	CardNumber []byte `json:"cardNumber"`
	CardExpirationMonth	string `json:"cardExpirationMonth"`
	CardExpirationYear	string `json:"cardExpirationYear"`
	CardType   string `json:"cardType"`
}
	
type TokenizeCardRequest struct {
	KeyID	string `json:"keyId"`
	CardInfo TokenCardDetails `json:"cardInfo"`
}

type InstrumentIdentifier struct {
	ID    string `json:"id"`
	New   string `json:"new"`
	State string `json:"state"`
}

type TokenizeSelf struct {
	Href string `json:"href"`
}

type TokenizeLinks struct {
	Links TokenizeSelf `json:"_links"`
}

type IcsReply struct {
	RequestID string `json:"requestId"`
	InstrumentIdentifier InstrumentIdentifier `json:"instrumentIdentifier"`
	TokenizeLinks TokenizeLinks `json:"_links"`
}

type Embedded struct {
	IcsReply IcsReply `json:"icsReply"`  
}

type DiscoverableServices struct {
	DiscoverableServices string `json:"discoverableServices"`
}	 
	
type TokenizeCardResponse struct {
	KeyId string `json:"keyId"`
	Token string `json:"token"`
	MaskedPan string `json:"maskedPan"`
	CardType string `json:"cardType"`
	Timestamp int64 `json:"timestamp"`
	SignedFields string `json:"signedFields"`
	Signature string `json:"signature"`
	DiscoverableServices DiscoverableServices `json:"discoverableServices"`
	Embedded Embedded `json:"_embedded"`
}


///////////////////////////////////////////////////////////////
//TokenAuthorization struct  /////////////////////////////////
/////////////////////////////////////////////////////////////
type ToCustomer struct {
	Id	string	`json:"id"`
}

type ToPaymentInformation struct {
	ToPaymentInformation	ToCustomer	`json:"customer"`
}
/*
type ToAmountDetails struct {
	totalAmount	string	`json:"totalAmount"`
	currency string `json:"currency"`	
}
*/
type ToOrderInformation struct {
	ToOrderInformation AmountDetails `json:"amountDetails"`
}

type TokenizeAuthRequest struct {
	ClientReferenceInformation	ClientReferenceInformation	`json:"clientReferenceInformation"`
	ToPaymentInformation	ToPaymentInformation	`json:"paymentInformation"`
	ToOrderInformation	ToOrderInformation	`json:"orderInformation"`
}

////////////////////////////////////////////////////////////////
// Authorization Reversal Struct //////////////////////////////
//////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
type RevAmountDetails struct {
  TotalAmount string   `json:"totalAmount"`
}
type ReversalInformation struct {
   RevAmountDetails RevAmountDetails `json:"amountDetails"`
   Reason string `json:"reason"`
}

type Reversal struct {
   	ClientReferenceInformation ClientReferenceInformation `json:"clientReferenceInformation"`
	ReversalInformation ReversalInformation `json:"reversalInformation"`
}

///////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
// Authorization Reversal Response Struct ///////////////////////////
////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////

//order_information
//type RevspCurrencyDetails struct {
   	//RevCurrency string `json:"currency"`
//}
type RevspAmountDetails struct {
   	RevspCurrency string `json:"currency"`
}
type RevspOrderInformation struct {
	RevspAmountDetails RevspAmountDetails `json:"amountDetails"`
}

//reversal_amount_details
type RevspRevAmountDetails struct {
   ReversedAmount string `json:"reversedAmount"`
   RevCurrency string `json:"currency"`
}
//type RevspRevAmountDetails struct {
	//RevspAmountDetails RevspAmountDetails `json:"amountDetails"`
//}
type RevProcessorInformation struct {
   RevResponseCode string `json:"responseCode"`
}
type RevspSelf struct {
        Method string `json:"method"`
        Href string `json:"href"`
}
type RevspLinks struct {
        RevspSelf RevspSelf `json:"self"`
}

//type ErrorInformation struct {
        //Reason  string `json:"reason"`
        //Message string `json:"message"`
//}

type AuthReversalResponse struct {
        RevspLinks RevspLinks `json:"_Links"`
	ClientReferenceInformation ClientReferenceInformation `json:"clientReferenceInformation"`
        RevId string `json:"id"`
        RevspOrderInformation RevspOrderInformation `json:"orderInformation"`
        RevspRevAmountDetails RevspRevAmountDetails `json:"reversalAmountDetails"`
        RevProcessorInformation RevProcessorInformation `json:"processorInformation"`
        Status string `json:"status"`
        SubmitTimeUtc string `json:"submitTimeUtc"`
        Message string `json:"message"`
        //Reason string `json:"reason"`
	ErrorInformation ErrorInformation `json:"errorInformation"`
}


///////////////////////////////////////////////////////////////////////
// RevResponse struct ////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////

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

///////////////////////////////////////////////////////////////////////
// Capture Payment struct ////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////
type CapAmountDetails struct {
        TotalAmount string  `json:"totalAmount"`
        Currency string `json:"currency"`       
}

type CaptureOrderInformation struct {
   CapAmountDetails CapAmountDetails `json:"amountDetails"`
}

type CapturePayment struct {
        ClientReferenceInformation ClientReferenceInformation `json:"clientReferenceInformation"`
        CaptureOrderInformation CaptureOrderInformation `json:"orderInformation"`
}

///////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////
// Payment Capture Response Struct //////////////////////////////////
////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////

//capture_amount_details
type CapspAmountDetails struct {
   CapturedAmount string `json:"totalAmount"`
   CapCurrency string `json:"currency"`
}
type CapspOrderInformation struct {
	CapspAmountDetails CapspAmountDetails `json:"amountDetails"`
}
type CapspSelf struct {
        Method string `json:"method"`
        Href string `json:"href"`
}
type VoidSelf struct {
        Method string `json:"method"`
        Href string `json:"href"`
}
type CapspLinks struct {
        VoidSelf VoidSelf `json:"void"`
        CapspSelf RevspSelf `json:"self"`
}

type PaymentCaptureResponse struct {
        CapspLinks CapspLinks `json:"_Links"`
	ClientReferenceInformation ClientReferenceInformation `json:"clientReferenceInformation"`
        CapId string `json:"id"`
        CapspAmountDetails CapspAmountDetails `json:"orderInformation"`
        ReconciliationId string `json:"reconciliationId"`
        Status string `json:"status"`
        SubmitTimeUtc string `json:"submitTimeUtc"`
        Message string `json:"message"`
        //Reason string `json:"reason"`
	ErrorInformation ErrorInformation `json:"errorInformation"`
}

///////////////////////////////////////////////////////////////////////
// Payment Capture User Response struct ////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////

type CapResponse struct {
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
	ErrorMsg string
}

/////////////////////////////////////////////////////
// Payment Capture Resposnse struct ////////////////
///////////////////////////////////////////////////
type PayCaptureResponse struct {

}
/*
 Links struct {
                Void struct {
                        Method string `json:"method"`
                        Href   string `json:"href"`
                } `json:"void"`
                Self struct {
                        Method string `json:"method"`
                        Href   string `json:"href"`
                } `json:"self"`
        } `json:"_links"`
        ClientReferenceInformation struct {
                Code string `json:"code"`
        } `json:"clientReferenceInformation"`
        ID               string `json:"id"`
        OrderInformation struct {
                AmountDetails struct {
                        TotalAmount string `json:"totalAmount"`
                        Currency    string `json:"currency"`
                } `json:"amountDetails"`
        } `json:"orderInformation"`
        ReconciliationID string    `json:"reconciliationId"`
        Status           string    `json:"status"`
        SubmitTimeUtc    time.Time `json:"submitTimeUtc"

*/

////////////////////////////////////////////////
//YapConnection-Structs///////////////////////
//////////////////////////////////////////////

type GWConnect struct {
	Payalgorithm string
	Payhost string
	Payurl string
	//Paydate string
	Paytarget string
	Paydigestedmsg string
	Paysignature string
	Paymerchantid string
	Paymerchantkey string
	Paysecretkey string
	Payload []byte
	//Payorigintarget string
}

type GWConfig struct {
	DumpPayload bool
	AutoGenTransactId bool
	LogToFile string
	Tokenurl string
	Tokentarget string
	Tokenkeyurl string
	Tokenkeytarget string
	Tokenorigintarget string
	Paymenturl string
	Paymenttarget string
	Reversalurl string
	Reversalmeth string
	Captureurl string
	Capturemeth string
}

var gw GWConnect	//Gateway Connect

//Gateway Config
var gwc = GWConfig {
	DumpPayload: true,
	AutoGenTransactId : true, 
	Tokenurl : "https://testflex.cybersource.com/cybersource/flex/v1/tokens", 
	Tokentarget : "post /flex/v1/tokens",
	Tokenkeyurl : "https://apitest.cybersource.com/flex/v1/keys",
	Tokenkeytarget : "post /flex/v1/keys",
	Tokenorigintarget : "koroma.co.za",
	Paymenturl : "https://apitest.cybersource.com/pts/v2/payments/",
	Paymenttarget : "post /pts/v2/payments/",
	Reversalurl : "https://apitest.cybersource.com",
	Reversalmeth : "post ",
	Captureurl : "https://apitest.cybersource.com",
	Capturemeth : "post ",
}

///////////////////////////////////////////////////////////////////////////
// DoGWConnect():  ///////////////////////////////////////////////////////
// what: takes metchant credentials and populate connection parameters///
// returns error (nil for success) /////////////////////////////////////
///////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////
func DoGWConnect(cshost, merchantid, merchantkey, merchantsecret string) error {

	if merchantid != "" && merchantkey != "" && merchantsecret != "" {
		gw = GWConnect {
                	Payalgorithm:"HmacSHA256",
                	//Paydate: "",
                	Payhost: cshost,
                	Paymerchantid: merchantid,                   //mockchant_01/Mockchant123
                	Paymerchantkey: merchantkey,
                	Paysecretkey: merchantsecret,
                	Paydigestedmsg: "",
                	Paysignature: "",
                	//Payorigintarget: "yourdomain.co.za",

        	}

		return nil
	} else {
		return errors.New("Unable to connect")
	}

} //endOf_DoGWConnect


/////////////////////////////////////////////////////////
// DoSwitchTo():                              /////////
// set master-merchant-authentication variables /////////
/////////////////////////////////////////////////////////
func DoSwitchTo(typ string) {

	////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////
	// Cybersource merchant account details
	////////////////////////////////////////////////////////////////////
	////////////////////////////////////////////////////////////////////
	//mymerchantid = "mockchant"			//mockchant_01/Mockchant123

	if typ == "2" || strings.ToLower(typ) == "key" || strings.ToLower(typ) == "keys" {		//Tokenkeys

		gw.Payurl = gwc.Tokenkeyurl
		gw.Paytarget = gwc.Tokenkeytarget

	} else if typ == "3" || strings.ToLower(typ) == "token" || strings.ToLower(typ) == "tokens" { //Tokenize

		gw.Payurl = gwc.Tokenurl
		gw.Paytarget = gwc.Tokentarget	

	} else if typ == "4" || strings.ToLower(typ) == "reversal" || strings.ToLower(typ) == "rev" { //Reversal

		gw.Payurl = gwc.Reversalurl
		gw.Paytarget = gwc.Reversalmeth

	} else if typ == "5" || strings.ToLower(typ) == "capture" || strings.ToLower(typ) == "cap" { //Capture

		gw.Payurl = gwc.Captureurl
		gw.Paytarget = gwc.Capturemeth
	} else {
		
		gw.Payurl = gwc.Paymenturl
		gw.Paytarget = gwc.Paymenttarget
	}
	
	//fmt.Println("\n::DoSwitchTo::paymenturl: "+gw.Payurl)
	//fmt.Println("\n::DoSwitchTo::paytarget: "+gw.Paytarget)
	//fmt.Println("\n::DoSwitchTo::Done\n")
	//fmt.Printf("\tDoSwitchTo::typ: %q\n", typ)
	//fmt.Println("\tDoSwitchTo::MasterMerchantAuth::payalgorithm: "+ gw.Payalgorithm) 
	//fmt.Println("\tDoSwitchTo::MasterMerchantAuth::payhost: "+ gw.Payhost) 
	//fmt.Println("\tDoSwitchTo::MasterMerchantAuth::paymenturl: "+ gw.Payurl)
	//fmt.Println("\tDoSwitchTo::MasterMerchantAuth::paytarget: "+gw.Paytarget)
	//fmt.Println("\tDoSwitchTo::MasterMerchantAuth::paymerchantid: "+gw.Paymerchantid) 
	//fmt.Println("\tDoSwitchTo::MasterMerchantAuth::paysecretkey: "+gw.Paysecretkey)
	//fmt.Println("\tDoSwitchTo::MasterMerchantAuth::paymerchantkey: "+gw.Paymerchantkey+ "\n")	

} //endOf_DoSwitchTo


///////////////////////////////////////
//DoHttpSendRcv()    //////////////////
//sends and receives http requests/////
///////////////////////////////////////
func DoHttpSendRcv(payload []byte) []byte {
	
	gw.Paysignature = DoSignatureStr()	//sign the header for auth
	
	timeout := time.Duration(86400 * time.Second)
	client := &http.Client{ 
		Transport: &http.Transport{MaxConnsPerHost: 50},
		Timeout: timeout,
	}
	
	req, err := http.NewRequest("POST", gw.Payurl, bytes.NewBuffer(payload))
	if err != nil { 
		//fmt.Println("\tDoHttpSendRcv::HTTPCreateRequest.....Error")
		//fmt.Println(err) 
	}

	//do_header enrichment
	req.Header.Del("Accept")
	req.Header.Set("host", gw.Payhost)
	req.Header.Set("date", DoGetPayDate())
	req.Header.Set("signature", gw.Paysignature)
	req.Header.Set("digest", gw.Paydigestedmsg)
	req.Header.Set("v-c-merchant-id", gw.Paymerchantid)
	req.Header.Set("content-Type", "application/json")
	req.Header.Set("user-Agent", "iAuthCS/0.1")
	
	if gwc.DumpPayload == true {
		dump, err := httputil.DumpRequestOut(req, true)
		if err != nil {
			//doErrorLog(err.Error())
		}
		fmt.Printf("\n\niauthcs_RequestPayloadDump:\n\t%s\n\n", dump)
	}

	resp, err := client.Do(req)	
	if err != nil { 
	} 

	data, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

        if gwc.DumpPayload == true {
                fmt.Printf("\n\niauthcs_ResponsePayloadDump:\n\t%s\n\n", data)
        }
	
	return data	
} //endOf_DoHttpSendRcv


////////////////////////////////////////////////////
// DoGetPayDate() /////////////////////////////////
//returns a RFC1123 format date specific for cs ///
/////////////////////////////////////////////////
////////////////////////////////////////////////
func DoGetPayDate() string {
	const (RFC1123 = "Mon, 02 Jan 2006 15:04:05 GMT")
	var pd = time.Now()

	return pd.Format(RFC1123)
} //endOf_DoGetPayDate


//////////////////////////////////////////
//DoCardTokenize()    ///////////////////
//makes a card tokenization request/////
///////////////////////////////////////
func DoCardTokenize(cardinfo []byte) []byte {

	fmt.Println("\n::DoCardTokenize::iAuthCS0.1 Does not implement card tokenization::")
	return []byte{}
} //endOf_DoCardTokenize


////////////////////////////////////////////////////////
//DoPayAuthorization()   //////////////////////////////
//executes a card payment authorization///////////////
/////////////////////////////////////////////////////
func DoPaymentAuth (cardnum, cardmth, cardyr, cardcvv, cardamt string) PayResponse {
			
	DoSwitchTo("PAYMENT")	//switch env to payment request		
	adata := DoHttpSendRcv(DoPayAuthPayload(cardnum, cardmth, cardyr, cardcvv, cardamt))
	
	var p PaymentAuthResponse	
	rerr := json.Unmarshal(adata, &p)
	if rerr != nil {  }
	
	//process response and return it
	return DoPayAuthResponse(&p)
} //endOf_DoPaymentAuth


////////////////////////////////////////////////////////////
//DoAuthReversal()   //////////////////////////////////////
//executes an authorization reversal//////////////////////
/////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
func DoAuthReversal(href, amount string) RevResponse {

	gwc.Reversalmeth =  gwc.Reversalmeth + href
	gwc.Reversalurl = gwc.Reversalurl + href

	DoSwitchTo("REVERSAL")	//switch env to auth reversal
	adata := DoHttpSendRcv(DoAuthReversalPayload(href, amount)) //get []byte payload and httpsend it
	
        var p AuthReversalResponse
        rerr := json.Unmarshal(adata, &p)
        if rerr != nil {  }
        
        //process response and return it
        return DoAuthReversalResponse(&p)
} //endOf_DoAuthReversal

//////////////////////////////////////////////////////////////
//DoPaymentCapture()   //////////////////////////////////////
//executes a card authorization reversal//////////////////
/////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
func DoPaymentCapture(href, amount string) CapResponse {
			
	gwc.Capturemeth =  gwc.Capturemeth + href
        gwc.Captureurl = gwc.Captureurl + href

	DoSwitchTo("CAPTURE")	//switch env to payment capture
	cdata := DoHttpSendRcv(DoPaymentCapturePayload(amount)) //get []byte payload and httpsend it
	
	var c PaymentCaptureResponse
        rerr := json.Unmarshal(cdata, &c)
        if rerr != nil {  }
        
	fmt.Printf("\t\nCaptureResponse: %s\n", cdata)

        //process response and return it
        return DoPaymentCaptureResponse(&c)
} //endOf_DoPaymentCapture()


//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
//DoTokenAuthorization()   //////////////////////////////////////
//executes a tokenized card payment authorization///////////////
///////////////////////////////////////////////////////////////
func DoTokenAuthorization(pay []byte) []byte {
	return []byte{}
} //endOf_DoTokenAuthorization

///////////////////////////////////////
//GetTokenizeResponse()    //////////////
//gets encryption key for tokenization/
///////////////////////////////////////
func doTokenizeResponse(t *TokenizeCardResponse) []byte {
	return []byte{}
} //endOf_doTokenizeResponse

/*
///////////////////////////////////////////////////////
// DoTokenStore()                                 /////
// persists the token to db 					 //////
///////////////////////////////////////////////////////
*/

////////////////////////////////////////////////////////////////////
// DoTokenKeyPayload()
// arg1: otarget: the target url for which the key is generated
// return: json payload for authorization
////////////////////////////////////////////////////////////////////
func DoTokenKeyPayload() []byte {
	return []byte{}
} //endOf_DoTokenKeyPayload

////////////////////////////////////////////////////
// DoTokenizePayload()             ////////////////
// return: json payload for card tokenization //////
////////////////////////////////////////////////////
func DoTokenizePayload(cryptnum, cardinfo []byte, keyid, cardtyp string) []byte {
	return []byte{}
} //endOf_DoTokenizePayload


////////////////////////////////////////////////////////////////////
// DoPayAuthPayload()          ////////////////////////////////////
// arg1: cardpay - []byte of the card payment string  ////////////
// return: json payload for authorization  ////////////////////// 
////////////////////////////////////////////////////////////////
func DoPayAuthPayload(cardnum, cardmth, cardyr, cardcvv, cardamt string) []byte {

	//var 0=tid, 1=cardnum, 2=exmonth, 3=exyear, 4=cvv, 5=amount, 6=name, 7=surname, 8=email
	amt := AmountDetails{cardamt, "USD"}
	bill := BillTo{"Alie", "Koroma", "KC", "8 Bokmakierie road", "Address 2", "Johannesburg", "Gauteng", "2181", "ZA", "alie@koroma.co.za", "27832602658"}
	card := Card{cardnum, cardmth, cardyr, cardcvv}
	cind := ProcessingInformation{"internet"}
	var tid string
	if gwc.AutoGenTransactId == true {
		tid = DoGetTID()
	} else {
		tid = DoGetTID()
	}

	code := ClientReferenceInformation{tid}
	// construct the complete payment authorazition request payload and convert it to json
	pay := Payment{code, cind, PaymentInformation{card}, OrderInformation{amt,bill}}
	
	
	// marshal the process struct
	pload, err := json.Marshal(pay)
	if err != nil {
		///////////////////////////////
		//HANDLE THIS ERROR PROPERLY
		///////////////////////////////
	}
	
	//digest the payload before returning
	gw.Paydigestedmsg = DoMessageDigest(pload)
	
	return pload
} //endOf_DoPayAuthPayload


/////////////////////////////////////////////////////////////////////
// DoAuthReversalPayload()          ////////////////////////////////////
// return: json payload for reversal /////  ////////////////////// 
/////////////////////////////////////////////////////////////////
func DoAuthReversalPayload(href, amount string) []byte {

	//cplit := strings.Split(href, "/")
	//tid := cplit[3]

	// prepare to send the payment auth request
	//the json payload marshalling (m, i, u, a
	//var 0=merchantTid, 1=gwTid, 2=url, 3=amount
	var tid string
	amt := RevAmountDetails{amount}
	rson := "iAuthCS authorization reversal"
	order := ReversalInformation{amt, rson}
        if gwc.AutoGenTransactId == true {
                tid = DoGetTID()
        } else {
                tid = DoGetTID()
        }    
        code := ClientReferenceInformation{tid}

	//construct the complete payment reversal request payload and convert it to json
	rev := Reversal{code, order}

	// marshal the process struct
	pload, err := json.Marshal(rev)
	if err != nil {

		///////////////////////////////
		//HANDLE THIS ERROR PROPERLY
		///////////////////////////////
	}

	//iauth.DigestedMsg = DoMessageDigest(pload)		//digest the payload before returning
	gw.Paydigestedmsg = DoMessageDigest(pload)		//digest the payload before returning
	
	return pload
} //endOf_DoAuthReversalPayload

/////////////////////////////////////////////////////////////////////
// DoPaymentCapturePayload()          ////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
func DoPaymentCapturePayload(amt string) []byte {

	// prepare the payment capture payload
	fmt.Println("DoPaymentCapturePayload::Start:...: "+ amt)
	
	var tid string
	//var amnt CapAmountDetails
	//var order CaptureOrderInformation
        if gwc.AutoGenTransactId == true {
                tid = DoGetTID()
        } else {
                tid = DoGetTID()
        }    
	amnt := CapAmountDetails{amt, "USD"}
	order := CaptureOrderInformation{amnt}

	code := ClientReferenceInformation{tid}
	//construct the complete payment reversal request payload and convert it to json
	ca := CapturePayment{code, order}

	// marshal the process struct
	pload, err := json.Marshal(ca)
	if err != nil {
		//doErrorLog("ERR_MARSHALING\t" + tid)
		//doErrorLog(err.Error())
		///////////////////////////////
		//HANDLE THIS ERROR PROPERLY
		///////////////////////////////
	}

	//iauth.DigestedMsg = DoMessageDigest(pload)		//digest the payload before returning
	gw.Paydigestedmsg = DoMessageDigest(pload)		//digest the payload before returning
	
	return pload
} //endOf_DoPaymentCapturePayload


////////////////////////////////////////////////////////////////////
// DoTokenAuthPayload()          ////////////////////////////////////
// arg1: topay - []byte of the card payment string  ////////////
// return: json payload for authorization  ////////////////////// 
////////////////////////////////////////////////////////////////
 func DoTokenAuthPayload(topay []byte) []byte {
	return []byte{}
} //endOf_DoTokenAuthPayload


////////////////////////////////////////////////////////////////////
// DoMessageDigest()
// arg1: msgToDigest - payment authorization payload
// return: SHA-256=/HJGVdGGWYt1b0LO7N9WDeElMZv1fimKajvmJHhutTI= 
////////////////////////////////////////////////////////////////////
func DoMessageDigest(msgToDigest []byte) string {
	
	h := sha256.New()
	h.Write(msgToDigest)
	byt_str := h.Sum(nil)	
	
	return strings.Join([]string{"SHA-256", base64.StdEncoding.EncodeToString(byt_str)}, "=")
} ;//endOf_doMessageDigest

//////////////////////////////////////////////////////////////////////////////
// signHeaders() ////////////////////////////////////////////////////////////
// returns: a string of the signed header fields ///////////////////////////
///////////////////////////////////////////////////////////////////////////
func signHeaders(signatureBtyeString []byte, secretKey string) string {

	dcoded_secret, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		//doErrorLog(err.Error())
	}
	mac := hmac.New(sha256.New, []byte(dcoded_secret))
	mac.Write(signatureBtyeString)
	base64_str := base64.StdEncoding.EncodeToString([]byte(mac.Sum(nil)))

	return strings.Replace(base64_str, "\n", "", -1)
} //endOf_signHeaders


//////////////////////////////////////////////////////////////////////////////
// getHeaderStrToSign() /////////////////////////////////////////////////////
// returns: a byte array of the signed header //////////////////////////////
///////////////////////////////////////////////////////////////////////////
func getHeaderStrToSign() []byte {
	// prepare the header for signing
	var h strings.Builder

	h.WriteString(strings.Join([]string{"host:", gw.Payhost}, " "))
	h.WriteString(strings.Join([]string{"\ndate:", DoGetPayDate()}, " "))
	h.WriteString(strings.Join([]string{"\n(request-target):", gw.Paytarget}, " "))
	h.WriteString(strings.Join([]string{"\ndigest:", gw.Paydigestedmsg}, " "))
	h.WriteString(strings.Join([]string{"\nv-c-merchant-id:", gw.Paymerchantid}, " "))
	signedHeaderByteStr := []byte(h.String())

	return signedHeaderByteStr 
} //endOf_getHeaderStrToSign

//////////////////////////////////////////////////////////////
// getSignedHeader() ////////////////////////////////////////
// returns: the signed header     //////////////////////////
///////////////////////////////////////////////////////////
func getSignedHeader() string {
	
	// sign the header string witht he secret key
	return signHeaders(getHeaderStrToSign(), gw.Paysecretkey)

} //endOf_getSignedHeader

////////////////////////////////////////////////////////////
// getHeaderList() ////////////////////////////////////////
// returns: list of header fields ////////////////////////
/////////////////////////////////////////////////////////
func getHeaderList() string {
	
	//build the headers values: headers="host date (request-target) v-c-merchant-id"
	return strings.Join([]string{"host", "date", "(request-target)", "digest", "v-c-merchant-id"}, " ")
} //endOf_getHeaderList

/////////////////////////////////////////////////////////////
// DoSignatureStr() ////////////////////////////////////////
// returns: header signature string ///////////////////////
// signature of the signed header fields /////////////////
/////////////////////////////////////////////////////////
func DoSignatureStr() string {
	
	// compose/compile the signature fields
	var p strings.Builder

	k := strconv.Quote(gw.Paymerchantkey)
	keyid := []string{"keyid", k}
	keyid_kv := strings.Join(keyid, "=")
	p.WriteString(keyid_kv + ", ")
	
	a := strconv.Quote(gw.Payalgorithm)
	alg := []string{"algorithm", a}
	alg_kv := strings.Join(alg, "=")
	p.WriteString(alg_kv + ", ")

	hd := strconv.Quote(getHeaderList())
	hdr := []string{"headers", hd}
	hdr_kv := strings.Join(hdr, "=")
	p.WriteString(hdr_kv + ", ")

	s := strconv.Quote(getSignedHeader())
	sig := []string{"signature", s}
	sig_kv := strings.Join(sig, "=")
	p.WriteString(sig_kv)

	return p.String()
} ;//endOf_GetSignatureStr

/////////////////////////////////////////////////////////////
// DoGetTID() //////////////////////////////////////////////
// returns: a key encoded as string ///////////////////////
////////////////////////////////////////////////////////// 
/////////////////////////////////////////////////////////
func DoGetTID() string {

	bytes := make([]byte, 4) //generate a random 4 byte key 
	if _, err := rand.Read(bytes); err != nil {
	    //doErrorLog(err.Error())
	}

	return hex.EncodeToString(bytes) //encode key in bytes to string for saving
} //endOf_DoGetTID


/////////////////////////////////////////////////
// DoRSAEncrypt()						/////////
//returns: encrypts into rsa algorithm cypher ///
/////////////////////////////////////////////////
func DoRSAEncrypt(strToEncrypt string, keyid string, rsakey string) []byte {
	return []byte{}
} //endOf_DoRSAEncrypt


//////////////////////////////////////////////////////////////////////////////////
// DoPayAuthResponse(): /////////////////////////////////////////////////////////
// marshals the payment authorization response and populate datastruct /////////
// for user access ////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
func DoPayAuthResponse(p *PaymentAuthResponse) PayResponse {

	r := PayResponse {
        	//extract the response values
        	AuthReversalMethod:  p.Links.AuthReversal.Method,
        	AuthReversalHref: p.Links.AuthReversal.Href,
  		SelfMeth: p.Links.Self.Method,
        	SelfHref: p.Links.Self.Href,
        	CaptureMeth:p.Links.Capture.Method,
        	CaptureHref: p.Links.Capture.Href,
  		ClientRefId: p.ClientReferenceInformation.Code,
        	TransactId: p.RespId,
        	Orderamt: p.RespOrderInformation.AmountDetails.AuthorizedAmount,
        	OrderCur: p.RespOrderInformation.AmountDetails.Currency,
        	CardType: p.PaymentAccountInformation.RespCard.Type,
        	TokenType: p.RespPaymentInformation.TokenizedCard.Type,
        	PointOfSaleId: p.PointOfSaleInformation.TerminalId,
        	ProcessorApprovalCode: p.ProcessorInformation.ApprovalCode,
        	ProcessorVerificationRCode: p.ProcessorInformation.CardVerification.Resultcode,
        	ProcessorNetworkTransactionId: p.ProcessorInformation.NetworkTransactionId,
        	ProcessorTransactionId: p.ProcessorInformation.TransactionId,
        	ProcessorResponseCode: p.ProcessorInformation.ResponseCode,
        	ProcessorAvsCode: p.ProcessorInformation.Avs.Code,
        	ProcessorAvsCodeRaw: p.ProcessorInformation.Avs.CodeRaw,
        	ReconciliationId: p.ReconciliationId,
        	ResponseStatus: p.RespStatus,
        	SubmitTimeUtc: p.SubmitTimeUtc,
        	ErrorMessage: p.ErrorInformation.Message,
	}

	return r
} //endOf_DoPayAuthResponse

//////////////////////////////////////////////////////////////////////////////////
// DoAuthReversalResponse(): /////////////////////////////////////////////////////
// marshals the authorization reversal response and populate datastruct /////////
// for easy user access ///////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
func DoAuthReversalResponse(r *AuthReversalResponse) RevResponse {

        ra := RevResponse {
		RevSelfMeth: r.RevspLinks.RevspSelf.Method,
        	RevSelfHref : r.RevspLinks.RevspSelf.Href,
        	ClientRefId : r.ClientReferenceInformation.Code,
        	TransactId : r.RevId,
        	OrderCur : r.RevspOrderInformation.RevspAmountDetails.RevspCurrency,
        	ProcessorResponseCode : r.RevProcessorInformation.RevResponseCode,
        	ReversedAmount : r.RevspRevAmountDetails.ReversedAmount,
        	ReversedCur : r.RevspRevAmountDetails.RevCurrency,
        	ResponseStatus : r.Status,
        	SubmitTimeUtc : r.SubmitTimeUtc,
        	ErrorMsg: r.ErrorInformation.Message,
	}

        return ra
} //endOf_DoAuthReversalResponse

//////////////////////////////////////////////////////////////////////////////////
// DoPaymentCaptureResponse(): //////////////////////////////////////////////////
// marshals the payment capture response and populates datastruct //////////////
// for easy user access ///////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
func DoPaymentCaptureResponse(r *PaymentCaptureResponse) CapResponse {

        pc := CapResponse {
		VoidMeth: r.CapspLinks.VoidSelf.Method,
        	VoidHref : r.CapspLinks.VoidSelf.Href,
		SelfMeth: r.CapspLinks.CapspSelf.Method,
        	SelfHref : r.CapspLinks.CapspSelf.Href,
        	ClientRefId : r.ClientReferenceInformation.Code,
        	TransactId : r.CapId,
        	OrderAmt : r.CapspAmountDetails.CapturedAmount,
        	OrderCur : r.CapspAmountDetails.CapCurrency,
        	ReconciliationId : r.ReconciliationId,
        	ResponseStatus : r.Status,
        	SubmitTimeUtc : r.SubmitTimeUtc,
        	ErrorMsg: r.ErrorInformation.Message,

	}

        return pc
} //endOf_DoPaymentCaptureResponse

