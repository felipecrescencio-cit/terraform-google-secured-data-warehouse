// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/base64"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	gofakeit "github.com/brianvoe/gofakeit/v6"

	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
)

const (
	minIssueYear   = "2000"
	maxIssueYear   = "2021"
	minCreditLimit = 999
	maxCreditLimit = 999999
)

var (
	issueBanks = []string{"Chase", "Wells Fargo", "Bank of America", "Capital One", "Barclays", "GE Capital", "U.S. Bancorp"}
	csvHeaders = []string{
		"Card Type Code",
		"Card Type Full Name",
		"Issuing Bank",
		"Card Number",
		"Card Holder's Name",
		"CVV/CVV2",
		"Issue Date",
		"Expiry Date",
		"Billing Date",
		"Card PIN",
		"Credit Limit",
	}
	khPriv *keyset.Handle
	khPub  *keyset.Handle
	enc    tink.HybridEncrypt
	dec    tink.HybridDecrypt
)

// generator config
type genCfg struct {
	seed     int64
	count    int
	filename string
}

// csv entry
type entry struct {
	cardTypeCode     string
	cardTypeFullName string
	issuingBank      string
	cardNumber       string
	cardHolderName   string
	cvv              string
	issueDate        string
	expiryDate       string
	billingDate      string
	cardPin          string
	limit            string
}

func (e entry) strSlice() []string {
	return []string{
		e.cardTypeCode,
		e.cardTypeFullName,
		e.issuingBank,
		e.cardNumber,
		e.cardHolderName,
		e.cvv,
		e.issueDate,
		e.expiryDate,
		e.billingDate,
		e.cardPin,
		e.limit,
	}
}

// issueBank generates a random issuing bank for a cc
func issueBank(faker *gofakeit.Faker, ccName string) string {
	switch ccName {
	case "American Express":
		return "American Express"
	case "Diners Club":
		return "Diners Club International"
	case "JCB":
		return "Japan Credit Bureau"
	case "Discover":
		return "Discover"
	default:
		return faker.RandomString(issueBanks)
	}
}

// ccShortCode generates a short code based on cc name
// https://github.com/brianvoe/gofakeit/blob/master/data/payment.go#L19 for supported ccTypes
func ccShortCode(ccName string) string {
	switch ccName {
	case "Visa":
		return "VI"
	case "Mastercard":
		return "MC"
	case "American Express":
		return "AX"
	case "Diners Club":
		return "DC"
	case "Discover":
		return "DS"
	case "JCB":
		return "JC"
	case "UnionPay":
		return "UP"
	case "Maestro":
		return "MT"
	case "Elo":
		return "EO"
	case "Mir":
		return "MR"
	case "Hiper":
		return "HR"
	case "Hipercard":
		return "HC"
	default:
		return "NA"
	}
}

// generateEntry generates a CSV entry
func generateEntry(faker *gofakeit.Faker) entry {
	e := entry{}
	minIssueT, err := time.Parse("2006-01-02", fmt.Sprintf("%s-01-01", minIssueYear))
	if err != nil {
		log.Fatal(err)
	}
	maxIssueT, err := time.Parse("2006-01-02", fmt.Sprintf("%s-01-01", maxIssueYear))
	if err != nil {
		log.Fatal(err)
	}
	// issued between min/max issue time
	issueTime := faker.DateRange(minIssueT, maxIssueT)
	e.issueDate = issueTime.Format("01/2006")
	e.cardHolderName = faker.Name()
	cc := faker.CreditCard()
	e.cvv = cc.Cvv

	e.cardNumber = encryptData(cc.Number)

	e.cardTypeFullName = cc.Type
	e.cardTypeCode = ccShortCode(cc.Type)
	// expiry is 3-5 years after issue
	expiryTime := faker.DateRange(issueTime.AddDate(3, 0, 0), issueTime.AddDate(5, 0, 0))
	e.expiryDate = expiryTime.Format("01/2006")
	e.issuingBank = issueBank(faker, cc.Type)
	e.billingDate = strconv.Itoa(faker.Number(1, 27))
	// 4 digit num
	e.cardPin = strconv.Itoa(faker.Number(1000, 9999))
	e.limit = strconv.Itoa(faker.Number(minCreditLimit, maxCreditLimit))
	return e
}

func parseFlags() genCfg {
	var c genCfg
	flag.Int64Var(&c.seed, "seed", 1, "Random seed for generator. Defaults to 1")
	flag.IntVar(&c.count, "count", 100, "Number of entries to generate. Defaults to 100")
	flag.StringVar(&c.filename, "filename", "", "Filename to write csv data. Defaults to data-${count}.csv")
	flag.Parse()
	if c.filename == "" {
		c.filename = fmt.Sprintf("data-%d.csv", c.count)
	}
	return c
}

func setupKeyset() {
	var err error

	f, err := os.Open("./pubkey.json")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	reader := keyset.NewJSONReader(f)

	khPub, err = keyset.ReadWithNoSecrets(reader)
	if err != nil {
		log.Fatal(err)
	}

	// khPriv2, err := keyset.NewHandle(hybrid.ECIESHKDFAES128GCMKeyTemplate())
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// TODO: save the private keyset to a safe location. DO NOT hardcode it in source code.
	// Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
	// See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

	// khPub2, err := khPriv.Public()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Println(khPub2)

	enc, err = hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		log.Fatal(err)
	}

	f2, err := os.Open("./keyset.json")
	if err != nil {
		log.Fatal(err)
	}
	defer f2.Close()

	reader2 := keyset.NewJSONReader(f2)

	// khPriv, err = keyset.ReadWithNoSecrets(reader2)
	khPriv, err = insecurecleartextkeyset.Read(reader2)

	if err != nil {
		log.Fatal(err)
	}

	dec, err = hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		log.Fatal(err)
	}

	// fmt.Println("enc ", enc)
	// fmt.Println("dec ", dec)
}

func encryptData(data string) string {
	// b, err := os.ReadFile("./pubkey.json") // just pass the file name
	// if err != nil {
	// 	fmt.Print(err)
	// }

	//reader := tink.JsonKeysetReader(json_pub)
	// reader := keyset.NewJSONReader(b)

	//kh_pub = cleartext_keyset_handle.read(reader)
	// khPub = khPriv.ReadWithNoSecrets(reader)

	msg := []byte(data)
	// encryptionContext := []byte("encryption context")
	encryptionContext := []byte("")

	ct, err := enc.Encrypt(msg, encryptionContext)
	if err != nil {
		log.Fatal(err)
	}

	pt, err := dec.Decrypt(ct, encryptionContext)
	if err != nil || pt == nil {
		log.Fatal(err)
	}
	// fmt.Printf("Ciphertext: %s\n", base64.StdEncoding.EncodeToString(ct))
	// fmt.Printf("Original  plaintext: %s\n", msg)
	fmt.Printf("Decrypted Plaintext: %s\n", pt)

	return base64.StdEncoding.EncodeToString(ct)
}

func main() {
	cfg := parseFlags()

	f, err := os.OpenFile(cfg.filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	err = writer.Write(csvHeaders)
	if err != nil {
		log.Fatal(err)
	}

	setupKeyset()

	faker := gofakeit.New(cfg.seed)
	for i := 0; i < cfg.count; i++ {
		e := generateEntry(faker)
		err = writer.Write(e.strSlice())
		if err != nil {
			log.Fatal(err)
		}
	}
}
