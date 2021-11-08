///////////////////////////////////////////////////////////////
//iauthcs_sample.go //////////////////////////////////////////
//desc: demostrates the use of the package //////////////////
//-the parameters are hard-coded for this reason////////////
//a list of test credit cards are avaialable on the net ///
//////////////////////////////////////////////////////////

package main

import (
	"fmt"
	"atkoroma/iauthcs"
)


func main() {

	fmt.Println("\t::iauthcs...demo::\n")

	// client connection parameters
	cshost := "apitest.cybersource.com"
	merchantid := "mockchant"
	merchantkey := "b9bfa32a-c79c-4e7a-91b7-591b33764a53"
	merchantsec := "CaODdX2A9j3KkEa+oMz/HRXt0511uIDjzB8o/hN4SgA="

	// connect to gateway with iauthcs
	iauthcs.DoGWConnect(cshost, merchantid, merchantkey, merchantsec)

	// switch environment to payment endpoint
	//iauthcs.DoSwitchTo("PAYMENT")

	//make a payment authorization request and store the response in pay
	pay := iauthcs.DoPaymentAuth("4111111111111111","10","2024","135","195.90")

	//print out the payment authorization response
	fmt.Println("\n\tPayResponse: ")
	fmt.Println("\tResponseStatus: " + pay.ResponseStatus)
	fmt.Println("\tAuthReversalMethod: " + pay.AuthReversalMethod)
	fmt.Println("\tAuthReversalHref: " + pay.AuthReversalHref)
	fmt.Println("\tCaptureMeth: " + pay.CaptureMeth)
	fmt.Println("\tCaptureHref: " + pay.CaptureHref)
	fmt.Println("\tClientRefId: " + pay.ClientRefId)
	fmt.Println("\tTransactId: " + pay.TransactId)
	fmt.Println("\tOrderamt: " + pay.Orderamt)
	fmt.Println("\tOrderCur: " + pay.OrderCur)
	fmt.Println("\tCardType: " + pay.CardType)
	fmt.Println("\tTokenType: " + pay.TokenType)
	fmt.Println("\tPointOfSaleId: " + pay.ProcessorResponseCode)
	fmt.Println("\tProcessorApprovalCode: " + pay.ProcessorApprovalCode)
	fmt.Println("\tProcessorVerificationRCode: " + pay.ProcessorVerificationRCode)
	fmt.Println("\tProcessorNetworkTransactionId: " + pay.ProcessorNetworkTransactionId)
	fmt.Println("\tProcessorTransactionId: " + pay.ProcessorTransactionId)
	fmt.Println("\tProcessorResponseCode: " + pay.ProcessorResponseCode)
	fmt.Println("\tProcessorAvsCode: " + pay.ProcessorAvsCode)
	fmt.Println("\tProcessorAvsCodeRaw: " + pay.ProcessorAvsCodeRaw)
	fmt.Println("\tReconciliationId: " + pay.ReconciliationId)
	fmt.Println("\tSubmitTimeUtc: " + pay.SubmitTimeUtc)
	fmt.Println("\tErrorMessage: " + pay.ErrorMessage)
	

	//fmt.Printf("\tPayResponseDump:\n\t %+v\n", pay)

	//The code below will either test a reversal or a capture                      
	//A payment authorization can either be reversed and captured
	//for that reason, only one section can be tested at a time

	/////////////////////////////////////////////////////////////////
	//Uncomment the if_statement below to test payment_REVERSAL ////
	///////////////////////////////////////////////////////////////
	//Do authorization reversal (note for an authorized transaction)
	//we are basically requesting to reverse the "AUTHORIZED" 
	if pay.ResponseStatus == "AUTHORIZED" { 

		//Do an authorzation reversal
		ar := iauthcs.DoAuthReversal(pay.AuthReversalHref, pay.Orderamt)

		//print out the full response of the above request
		fmt.Println("\n\n\n\tAUTHORIZATION REVERSAL: "+"\n")
		fmt.Println("\tRevSelfMeth: " + ar.RevSelfMeth)
		fmt.Println("\tRevSelfHref: " + ar.RevSelfHref)
		fmt.Println("\tClientRefId: " + ar.ClientRefId)
		fmt.Println("\tTransactId: " + ar.TransactId)
		fmt.Println("\tOrderCur: " + ar.OrderCur)
		fmt.Println("\tProcessorResponseCode: " + ar.ProcessorResponseCode)
		fmt.Println("\tReversedAmount: " + ar.ReversedAmount)
		fmt.Println("\tReversedCur: " + ar.ReversedCur)
		fmt.Println("\tResponseStatus: " + ar.ResponseStatus)
		fmt.Println("\tSubmitTimeUtc: " + ar.SubmitTimeUtc)
		fmt.Println("\tErrorMsg: " + ar.ErrorMsg)

		fmt.Printf("\n\n\n\tAuthorization Reversal Response: %s" , ar)
	}

	/////////////////////////////////////////////////////////////////
	//Uncomment the if_statement below to test payment_CAPTURE  ////
	///////////////////////////////////////////////////////////////
	//Do payment capture
	//we are basically requesting that the reserved funds be transfered to us :)
	/*
	if pay.ResponseStatus == "AUTHORIZED" {
		fmt.Println("\n\n\n\tPayment Capture: " + pay.CaptureHref)
		fmt.Println("\n\n\n\tPayment Capture: " + pay.Orderamt)

		pc := iauthcs.DoPaymentCapture(pay.CaptureHref, pay.Orderamt)

		fmt.Printf("\n\tpc.ResponseStatus: %s" , pc.ResponseStatus)
		fmt.Printf("\n\n\n\tpc.ResposnePayloadDump: %s", pc)
	}
	*/
}
