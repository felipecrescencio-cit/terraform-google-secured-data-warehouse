# HOW-TO USE BIGQUERY ENCRYPTION FUNCTIONS WITH TINK

## In Bigquery

- Google Standard SQL for BigQuery supports the some AEAD encryption functions
- Make sure you create a key using one of the following types:
  - AEAD_AES_GCM_256 - For Tinkey use `AES256_GCM` type
  - DETERMINISTIC_AEAD_AES_SIV_CMAC_256

- Create a new Tink Keyset using BigQuery

```sql
SELECT KEYS.NEW_KEYSET('AEAD_AES_GCM_256') AS raw_keyset
```

- The key will be generated in bytes and returned base64 encoded

**Note:** Key, KMS Master Key and BigQuery tables MUST BE at same location (region, multi-region)

## In your terminal

- Decode your key and save it to a file
- Wrap the key with your KMS Master Key

```bash
KEY_ENCODED_FROM_BIGQUERY="<YOUR GENERATED KEY FROM BIGQUERY> - Looks like CK3245gBE..."
KMS_KEY="projects/my_project/locations/my_location/keyRings/my_keyring/cryptoKeys/my_key"

#Decode your key and save it to a file
echo $KEY_ENCODED_FROM_BIGQUERY | base64 --decode > /tmp/key_decoded

# Wrap the key with your KMS Master Key
gcloud kms encrypt --plaintext-file=/tmp/key_decoded --key=$KMS_KEY --ciphertext-file=/tmp/key_wrapped

# Dump key in format octal bytes that can be stored and used in BigQuery SQL
od -An --format=o1 /tmp/key_wrapped | tr -d '\n' | tr ' ' '\'
```

- Create your encrypted data file using your key i.e. `/tmp/key_decoded` with the Tink library in your preferred programming language
- The snippet code below creates a CSV with mock credit card data
  - The column *Card Number Encrypted* has the generated credit card number encrypted using Tink library in golang
  - The column *Card Number Plain* has the generated plain text credit card number for purposes of checking data

```go
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

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/insecurecleartextkeyset"
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
		"Card Number Encrypted",
		"Card Number Plain",
		"Card Holder's Name",
		"CVV/CVV2",
		"Issue Date",
		"Expiry Date",
		"Billing Date",
		"Card PIN",
		"Credit Limit",
	}
	khPub *keyset.Handle
	enc   tink.HybridEncrypt

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
type entry struct {
	cardTypeCode     string
	cardTypeFullName string
	issuingBank      string
	cardNumber       string
	cardNumberPlain  string
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
		e.cardNumberPlain,
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
	e.cardNumberPlain = cc.Number

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

func encryptKeyWithKMSMasterKey(deckeyfile string, enckeyfile string) {
	f, err := os.Open(deckeyfile)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	reader := keyset.NewJSONReader(f)

	khPub, err = keyset.ReadWithNoSecrets(reader)

	// private key
	// "github.com/google/tink/go/insecurecleartextkeyset"
	// khPub, err = insecurecleartextkeyset.Read(reader)

	if err != nil {
		log.Fatal(err)
	}

	f2, err := os.OpenFile(enckeyfile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		log.Fatal(err)
	}
	defer f2.Close()

	writer := keyset.NewBinaryWriter(f2)

	// An io.Reader and io.Writer implementation which simply writes to memory.
	// memKeyset := &keyset.MemReaderWriter{}

	masterKey, err := loadMasterKeyFromKMS()

	// Write encrypts the keyset handle with the master key and writes to the
	// io.Writer implementation (memKeyset). We recommend that you encrypt the
	// keyset handle before persisting it.
	if err := khPub.Write(writer, masterKey); err != nil {
		log.Fatal(err)
	}
}

func setupKeyset() {
	var err error

	f, err := os.Open("/tmp/key_decoded")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	reader := keyset.NewBinaryReader(f)

	masterKey, err := loadMasterKeyFromKMS()
	if err != nil || masterKey == nil {
		log.Fatal(err)
	}

	// khPub, err = keyset.Read(reader, masterKey)
	khPub, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		log.Fatal(err)
	}

	enc, err = aead.New(khPub)
	if err != nil {
		log.Fatal(err)
	}
}

func encryptData(data string) string {
	msg := []byte(data)
	encryptionContext := []byte("")

	ct, err := enc.Encrypt(msg, encryptionContext)
	if err != nil {
		log.Fatal(err)
	}

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
```

- To run the above code you will need [Go](https://go.dev/doc/install) 1.16+
- Create a file `main.go` and paste the code above
- Run the following Go commands to init a project, download libraries and run the code:

```bash
go mod init main
go get -u
go run main.go
```

- It will create a `data-100.csv` file in the same folder with mock credit card data

## In BigQuery


- Create a table in BigQuery to store you encrypted key
- The key column should have type `BYTES`
- Execute the script below in your terminal to generate a SQL insert into script to create your key record in your new table

```bash
KEY_DATASET_NAME="key-table"
KEY_TABLE_NAME="key-table"
KEY_TABLE_COLUMN_NAME="key"
echo "insert into \`$KEY_DATASET_NAME.$KEY_TABLE_NAME\`($KEY_TABLE_COLUMN_NAME) values (b'$(od -An --format=o1 /tmp/key_wrapped | tr -d '\n' | tr ' ' '\')')"
```

- You can ignore the `tr: warning: ...` if it appears
- Run the output insert into script in a BigQuery query window
- The SQL snippet below is an example on how to decrypt a message using your key in BigQuery

```sql
DECLARE kms_resource_name STRING;
DECLARE encrypted_msg STRING;
DECLARE first_level_keyset BYTES;

SET encrypted_msg='<YOUR BASE64 ENCRYPTED MESSAGE>';

SET kms_resource_name = 'gcp-kms://projects/my_project/locations/my_location/keyRings/my_keyring/cryptoKeys/my_key';

set first_level_keyset = (SELECT key FROM `<YOUR KEY DATASET NAME>.<YOUR KEY TABLE NAME>`);

SELECT AEAD.DECRYPT_STRING(KEYS.KEYSET_CHAIN(KMS_RESOURCE_NAME, first_level_keyset), FROM_BASE64(encrypted_msg), '');
```

### References

- [How to use KEYS.KEYSET_CHAIN in BigQuery](https://stackoverflow.com/questions/70200560/how-to-use-keys-keyset-chain-in-bigquery)
- [SQL in BigQuery - AEAD encryption functions](https://cloud.google.com/bigquery/docs/reference/standard-sql/aead_encryption_functions)
