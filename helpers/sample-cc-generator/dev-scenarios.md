# DEVELOPMENT SCENARIOS

1. What is the best practice to store wrapped DEK and use it to decrypt data without having it hardcoded in queries?

## Scenarios

Considering the Credit Card CSV with Card Number column encrypted.

### Wrapped DEK Hardcoded in SQL Query - WORKING

This query works fine with `kms_resource_name` and `first_level_keyset` hardcoded in KEYS.KEYSET_CHAIN method.

```sql
SELECT
  AEAD.DECRYPT_STRING(

    KEYS.KEYSET_CHAIN(
      'gcp-kms://projects/<suppressed>', --kms_resource_name
       b'\012\044\000 <suppressed>' ) , --first_level_keyset

    FROM_BASE64(Card_Number_Encrypted), --ciphertext
    "" --additional_data
  ) AS Card_Number_Decrypted,

FROM `<project>.<dataset>.<table>`
```

---

### Wrapped DEK retrieved from key-table in SQL Query - NOT WORKING

When I moved the `first_level_keyset` (keyset in bytes) to a row in table `key-table` and tried to retrieve it with this query:

```sql
SELECT
  AEAD.DECRYPT_STRING(

    KEYS.KEYSET_CHAIN(
      'gcp-kms://projects/<suppressed>', --kms_resource_name
       ( SELECT key FROM `pr-tink-372313.ds_tink_372313_us.key-table` ) ) , --first_level_keyset

    FROM_BASE64(Card_Number_Encrypted), --ciphertext
    "" --additional_data
  ) AS Card_Number_Decrypted,

FROM `pr-tink-372313.ds_tink_372313_us.cc-sample`
```

Got error: `Argument 2 to KEYS.KEYSET_CHAIN must be a literal or query parameter at [6:8]`

---

### Wrapped DEK retrieved from key-table in a STRUCT to compose KEYSET - NOT WORKING

I also tried to create the keyset struct from the scratch:

```sql
SELECT
  AEAD.DECRYPT_STRING(

    STRUCT( --keyset
        'gcp-kms://projects/<suppressed>' AS kms_resource_name,
        (SELECT key FROM `pr-tink-372313.ds_tink_372313_us.key-table`) AS first_level_keyset,
        CAST( NULL AS BYTES) as second_level_keyset
    ),

    FROM_BASE64(Card_Number_Encrypted), --ciphertext
    ""  --additional_data
  ) AS Card_Number_Decrypted,

FROM `pr-tink-372313.ds_tink_372313_us.cc-sample`
```

Got error: `The STRUCT input to encryption functions must be the direct output of KEYS.KEYSET_CHAIN function without transformations.`

---

### Wrapped DEK hardcoded in `bq` as parameter - WORKING

```bash
bq query \
    --use_legacy_sql=false \
    --parameter='kmskey::gcp-kms://projects/<suppressed>' \
    --parameter='key:BYTES:CiQAocmXuTr7x1YVw <suppressed>' \
    'SELECT
  Card_Type_Code,
  Issuing_Bank,
  Card_Number_Encrypted,

  AEAD.DECRYPT_STRING(
    KEYS.KEYSET_CHAIN(
      @kmskey ,
      @key ) ,

    FROM_BASE64(Card_Number_Encrypted),
    "" ) AS Card_Number_Decrypted,
    Card_Number_Plain
FROM `pr-tink-372313.ds_tink_372313_us.cc-sample`;'
```

---

### Plain DEK retrieved from key-table in SQL Query - WORKING

```sql
SELECT
  AEAD.DECRYPT_STRING(

    -- Get Key in plain bytes from Key Table
    KEYS.ADD_KEY_FROM_RAW_BYTES(
      ( SELECT key FROM `ds_tink_372313_us.key_plain` ) , --plain_keyset
      'AES_GCM', --key_type
      b'9876543210543210' --raw_key_bytes added to keyset > not used
    ),

  FROM_BASE64(Card_Number_Encrypted), --ciphertext
  '' --additional_data
) AS plaintext

FROM `pr-tink-372313.ds_tink_372313_us.cc-sample`
```
