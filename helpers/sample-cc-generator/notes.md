Based on: https://stackoverflow.com/questions/70200560/how-to-use-keys-keyset-chain-in-bigquery

In Bigquery:
- Create a new Tink Keyset using BigQuery

```sql
SELECT KEYS.NEW_KEYSET('AEAD_AES_GCM_256') AS raw_keyset
```

- The key will be generated in bytes and returned base64 encoded

**Note:** Key, KMS Master Key and BigQuery tables MUST BE at same location (region, multi-region)

In your terminal:

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
- The code presented below is a snippet on how to encrypt a string message using Tink library in golang

```go
package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

func main() {
	f, err := os.Open("/tmp/key_decoded")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	reader := keyset.NewBinaryReader(f)

	kh, err := insecurecleartextkeyset.Read(reader)
	if err != nil || kh == nil {
		log.Fatal(err)
	}

	a, err := aead.New(kh)

	data2 := []byte("lorem ipsum")

	msg, err := a.Encrypt(data2, []byte(""))

	fmt.Println("Encrypted message:", base64.StdEncoding.EncodeToString(msg))
}
```

- Create a table in BigQuery to store you encrypted key
- The key column should have type `BYTES`
- Execute the script below in your terminal to generate a SQL insert into script to create your key record in your new table

```bash
KEY_TABLE_NAME="key-table"
KEY_TABLE_COLUMN_NAME="key"
echo "insert into \`$KEY_TABLE_NAME\`($KEY_TABLE_COLUMN_NAME) values (b'$(od -An --format=o1 /tmp/key_wrapped | tr -d '\n' | tr ' ' '\')')"
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

set first_level_keyset = (SELECT key FROM `pr-tink-372313.ds_tink_372313_us.key-table`);

SELECT AEAD.DECRYPT_STRING(KEYS.KEYSET_CHAIN(KMS_RESOURCE_NAME, first_level_keyset), FROM_BASE64(encrypted_msg), '');
```
