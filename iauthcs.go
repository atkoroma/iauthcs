//iauthcs.go
//(c)2021 koroma_consulting 
//author: alie@koroma.co.za(alie.tormusa.koroma)

package iauthcs

import (
	"fmt"
	"time"
	"bytes"
	"errors"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"crypto/sha256"
	"crypto/rand"
	"crypto/hmac"
	"strings"
	"strconv"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
)

////////////////////////////////////////////////////
////////////////////////////////////////////////////
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
   PaymentInformation PaymentInformation `json:"paymentInformation"`
   OrderInformation OrderInformation `json:"orderInformation"`
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

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

type RespId struct {
   RespId string `json:"id"`
}

type RespAmountDetails struct {
  AuthorizedAmount string   `json:"authorizedAmount"`
  Currency string       `json:"currency"`
}
type RespOrderInformation struct {
   AmountDetails RespAmountDetails `json:"amountDetails"`
}

type RespCard struct {
   Type string        `json:"type"`
}
type PaymentAccountInformation struct {
  RespCard RespCard     `json:"card"`
}

type TokenizedCard struct {
   Type string        `json:"type"`
}
type RespPaymentInformation struct {
  TokenizedCard TokenizedCard     `json:"tokenizedCard"`
}

type PointOfSaleInformation struct {
   TerminalId string `json:"terminalId"`
}

type AVS struct {
   Code string `json:"code"`
   CodeRaw string `json:"codeRaw"`
}

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

/////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////
////////////////////////////////////////////////////
// PaymentRequest_Struct
////////////////////////////////////////////////////
///////////////////////////////////////////////////
/*
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

type ReversalOrderInformation struct {
   AmountDetails AmountDetails `json:"amountDetails"`
}

type Payment struct {
   ClientReferenceInformation ClientReferenceInformation `json:"clientReferenceInformation"`
   ProcessingInformation ProcessingInformation `json:"processingInformation"`
   //AggregatorInformation AggregatorInformation `json:"aggregatorInformation"`
   PaymentInformation PaymentInformation `json:"paymentInformation"`
   OrderInformation OrderInformation `json:"orderInformation"`
}
*/

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

//_links_information
/*
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
*/

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


//////////////////////////////////////////
//Tokenize card request+response structs//
//////////////////////////////////////////

///////////////////////////////////////////////////
type YapAuthConnect struct {
	Paymenturl string
	Paytarget string
}

type YapReversalConnect struct {
	Paymenturl string
	Paytarget string
}

type YapTokenKeyConnect struct {
	Tokenkeyurl string
	Tokenkeytarget string
	Origintarget string	
}

type YapTokenConnect struct {
	Tokenurl string
	Tokentarget string
}

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
	Payorigintarget string
}

type GWConfig struct {
	DumpPayload bool
	AutoGenTransactId bool 
}

var gw GWConnect	
var gwc GWConfig	

///////////////////////////////////////////////////////////////////////////
// DoGWConnect():  ///////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////
func DoGWConnect(cshost, merchantid, merchantkey, merchantsecret string) error {

	if merchantid != "" && merchantkey != "" && merchantsecret != "" {
		gw = GWConnect {
                	Payalgorithm:"HmacSHA256",
                	//Paydate: "",
                	Payhost: cshost,
                	Paymerchantid: merchantid,
                	Paymerchantkey: merchantkey,
                	Paysecretkey: merchantsecret,
                	Paydigestedmsg: "",
                	Paysignature: "",
                	Payorigintarget: "yourdomain.co.za",
        	}

		return nil
	} else {
		return errors.New("Unable to connect")
	}

} //endOf_DoGWConnect


/////////////////////////////////////////////////////////
// DoSwitchTo():                              /////////
/////////////////////////////////////////////////////////
func DoSwitchTo(typs...string) {

	var typ, swchr string
        for i, n := range typs {
                if i == 0 { typ = n }
                if i == 1 { swchr = n; _=swchr }
        }

	if typ == "2" || strings.ToLower(typ) == "key" || strings.ToLower(typ) == "keys" {		//Tokenkeys

		k := YapTokenKeyConnect {
			//init variables to be set
			Tokenkeyurl: "https://apitest.cybersource.com/flex/v1/keys",
			Tokenkeytarget: "post /flex/v1/keys",
			Origintarget: gw.Payorigintarget,
		}
		gw.Payurl = k.Tokenkeyurl
		gw.Paytarget = k.Tokenkeytarget

	} else if typ == "3" || strings.ToLower(typ) == "token" || strings.ToLower(typ) == "tokens" { //Tokenize

		t := YapTokenConnect {
			//init variables to be set
			Tokenurl: "https://testflex.cybersource.com/cybersource/flex/v1/tokens",
			Tokentarget: "post /flex/v1/tokens",
		}
		gw.Payurl = t.Tokenurl
		gw.Paytarget = t.Tokentarget	

	} else if typ == "4" || strings.ToLower(typ) == "reversal" || strings.ToLower(typ) == "rev" { //Reversal
		re := YapReversalConnect {			//AuthReversal
			//init variables to be set
			Paymenturl: "https://apitest.cybersource.com"+swchr,
			Paytarget: "post "+swchr,
		}
		gw.Payurl = re.Paymenturl
		gw.Paytarget = re.Paytarget

	} else {
		
		a := YapAuthConnect {				//Authorize
			//init variables to be set
			Paymenturl: "https://apitest.cybersource.com/pts/v2/payments/",
			Paytarget: "post /pts/v2/payments/",
		}
		gw.Payurl = a.Paymenturl
		gw.Paytarget = a.Paytarget
	}
	
} //endOf_DoSwitchTo


///////////////////////////////////////////////////////
//DoHttpSendRcv()    /////////////////////////////////
///////////////////////////////////////////////////
func DoHttpSendRcv(payload []byte) []byte {
	
	gw.Paysignature = DoSignatureStr()	
	
	timeout := time.Duration(86400 * time.Second)
	client := &http.Client{ 
		Transport: &http.Transport{MaxConnsPerHost: 50},
		Timeout: timeout,
	}
	
	req, err := http.NewRequest("POST", gw.Payurl, bytes.NewBuffer(payload))
	if err != nil { 
	}

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
		fmt.Printf("%s\n", dump)
	}
	
	resp, err := client.Do(req)	
	if err != nil { 
	} 

	data, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	
	return data	
} //endOf_DoHttpSendRcv


////////////////////////////////////////////////////
// DoGetPayDate() /////////////////////////////////
/////////////////////////////////////////////////
////////////////////////////////////////////////
func DoGetPayDate() string {
	const (RFC1123 = "Mon, 02 Jan 2006 15:04:05 GMT")
	var pd = time.Now()
	
	return pd.Format(RFC1123)
} //endOf_DoGetPayDate


///////////////////////////////////////////////
//getCardNum()
///////////////////////////////////////////////
func getCardNum(cardinfo []byte) string {
	
	paydelimit := []byte{' '}
    	cardPaySplit := bytes.Split(cardinfo, paydelimit)

	return string(cardPaySplit[1])
} //endOf_getCardNum


////////////////////////////////////////////////////////
//DoPayAuthorization()   //////////////////////////////
/////////////////////////////////////////////////////
func DoPayAuthorization(cardnum, cardmth, cardyr, cardcvv, cardamt string) PayResponse {

	DoSwitchTo("PAYMENT")
	adata := DoHttpSendRcv(DoPayAuthPayload(cardnum, cardmth, cardyr, cardcvv, cardamt))

	var p PaymentAuthResponse
	rerr := json.Unmarshal(adata, &p)
	if rerr != nil {  }

	return DoPayAuthResponse(&p)
} //endOf_DoPayAuthorization


////////////////////////////////////////////////////////////////////
// DoPayAuthPayload()          ////////////////////////////////////
////////////////////////////////////////////////////////////////
func DoPayAuthPayload(cardnum, cardmth, cardyr, cardcvv, cardamt string) []byte {

	amt := AmountDetails{cardamt, "USD"}
	bill := BillTo{"AT", "Koroma", "KoromaConsulting", "8 Bokmakierie road", "Randburg", "Johannesburg", "Gauteng", "2181", "ZA", "alie@koroma.co.za", "27832602658"}
	card := Card{cardnum, cardmth, cardyr, cardcvv}
	cind := ProcessingInformation{"internet"}
	var code ClientReferenceInformation       
	if gwc.AutoGenTransactId == false {
		code = ClientReferenceInformation{DoGetTID()}
	} else {
		code = ClientReferenceInformation{DoGetTID()}
	}
	pay := Payment{code, cind, PaymentInformation{card}, OrderInformation{amt,bill}}
	
	pload, err := json.Marshal(pay)
	if err != nil {
	}
	
	gw.Paydigestedmsg = DoMessageDigest(pload)
	
	return pload
} //endOf_DoPayAuthPayload


////////////////////////////////////////////////////////////////////
// DoMessageDigest()
////////////////////////////////////////////////////////////////////
func DoMessageDigest(msgToDigest []byte) string {
	
	h := sha256.New()
	h.Write(msgToDigest)
	byt_str := h.Sum(nil)	
	
	return strings.Join([]string{"SHA-256", base64.StdEncoding.EncodeToString(byt_str)}, "=")
} ;//endOf_doMessageDigest

//////////////////////////////////////////////////////////////////////////////
// signHeaders() ////////////////////////////////////////////////////////////
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
///////////////////////////////////////////////////////////////////////////
func getHeaderStrToSign() []byte {

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
///////////////////////////////////////////////////////////
func getSignedHeader() string {
	
	return signHeaders(getHeaderStrToSign(), gw.Paysecretkey)
} //endOf_getSignedHeader

////////////////////////////////////////////////////////////
// getHeaderList() ////////////////////////////////////////
/////////////////////////////////////////////////////////
func getHeaderList() string {
	
	return strings.Join([]string{"host", "date", "(request-target)", "digest", "v-c-merchant-id"}, " ")
} //endOf_getHeaderList

/////////////////////////////////////////////////////////////
// DoSignatureStr() ////////////////////////////////////////
/////////////////////////////////////////////////////////
func DoSignatureStr() string {
	
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
////////////////////////////////////////////////////////// 
/////////////////////////////////////////////////////////
func DoGetTID() string {

	bytes := make([]byte, 4) 
	if _, err := rand.Read(bytes); err != nil {
	    //doErrorLog(err.Error())
	}

	return hex.EncodeToString(bytes)
} //endOf_DoGetTID


//////////////////////////////////////////////////////////////////////////////////
// DoPayAuthResponse(): /////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
func DoPayAuthResponse(p *PaymentAuthResponse) PayResponse {

	r := PayResponse {
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
} //endOf_doPayAuthResponse
