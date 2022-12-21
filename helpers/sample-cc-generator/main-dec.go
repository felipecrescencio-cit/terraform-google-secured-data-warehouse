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
	"flag"
	"fmt"
	"log"
	"os"

	gofakeit "github.com/brianvoe/gofakeit/v6"

	"github.com/gocarina/gocsv"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/integration/gcpkms"
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
	dec    tink.HybridDecrypt

	// Change this. AWS KMS, Google Cloud KMS and HashiCorp Vault are supported out of the box.
	keyURI          = os.Getenv("KEY_URI")
	credentialsPath = os.Getenv("GCP_CRED_PATH")
)

// generator config
type genCfg struct {
	seed     int64
	count    int
	filename string
}

// csv entry
type Entry struct {
	CardTypeCode     string `csv:"Card Type Code"`
	CardTypeFullName string `csv:"Card Type Full Name"`
	IssuingBank      string `csv:"Issuing Bank"`
	CardNumber       string `csv:"Card Number"`
	CardHolderName   string `csv:"Card Holder's Name"`
	Cvv              string `csv:"CVV/CVV2"`
	IssueDate        string `csv:"Issue Date"`
	ExpiryDate       string `csv:"Expiry Date"`
	BillingDate      string `csv:"Billing Date"`
	CardPin          string `csv:"Card PIN"`
	Limit            string `csv:"Credit Limit"`
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

	f, err := os.Open("./keyset-enc")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	reader := keyset.NewBinaryReader(f)

	masterKey, err := loadMasterKeyFromKMS()
	if err != nil {
		log.Fatal(err)
	}

	// khPriv, err = keyset.ReadWithNoSecrets(reader2)
	// khPriv, err = insecurecleartextkeyset.Read(reader)
	khPriv, err = keyset.Read(reader, masterKey)

	if err != nil {
		log.Fatal(err)
	}

	dec, err = hybrid.NewHybridDecrypt(khPriv)
	if err != nil {
		log.Fatal(err)
	}
}

func decryptData(data string) string {
	msg, err := base64.StdEncoding.DecodeString(data)
	// encryptionContext := []byte("encryption context")
	encryptionContext := []byte("")

	pt, err := dec.Decrypt(msg, encryptionContext)
	if err != nil || pt == nil {
		log.Fatal(err)
	}

	return string(pt)
}

func loadMasterKeyFromKMS() (tink.AEAD, error) {
	// Fetch the master key from a KMS.
	gcpClient, err := gcpkms.NewClientWithCredentials(keyURI, credentialsPath)
	if err != nil {
		log.Fatal(err)
	}
	registry.RegisterKMSClient(gcpClient)
	masterKey, err := gcpClient.GetAEAD(keyURI)
	if err != nil {
		log.Fatal(err)
	}

	return masterKey, err
}

func main() {
	// cfg := parseFlags()
	setupKeyset()

	in, err := os.Open("./data-100.csv")
	if err != nil {
		panic(err)
	}
	defer in.Close()

	entries := []*Entry{}

	if err := gocsv.UnmarshalFile(in, &entries); err != nil {
		panic(err)
	}
	for _, client := range entries {
		fmt.Println(decryptData(client.CardNumber))
	}
}
