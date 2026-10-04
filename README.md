# mbdecrypt

A Metabase driver for SQL Server databases with application-level encrypted columns. It decrypts values as query
results come back, so Metabase shows plaintext.

It's an alternative to a pipeline (Debezium and Kafka, or a sync job) that copies decrypted data into another database,
for when that extra infrastructure isn't worth it.

## Getting started

### 1. Download the plugin

Get `sqlserver-decrypt.metabase-driver.jar` from the [latest release](../../releases/latest).

### 2. Install it

Put the jar in Metabase's plugins directory:

* **Docker:** mount a directory at `/plugins`.
* **JAR:** the `plugins` directory next to `metabase.jar`, or wherever `MB_PLUGINS_DIR` points.

### 3. Add the database

Restart Metabase, go to **Admin settings → Databases → Add database** and choose **SQL Server (decrypt)**. Fill in the
usual SQL Server connection details and **Decryptors**, one `<decryptor>` element for each way your application
encrypts:

```xml
<decryptor name="pii" algorithm="aes-256-gcm" key="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"/>
<decryptor name="legacy" algorithm="aes-128-cbc" key="f0e0d0c0b0a090807060504030201000" iv="0f0e0d0c0b0a09080706050403020100"/>
```

| Attribute | |
|---|---|
| `name` | Letters and digits, case-insensitive. Queries and rules refer to the decryptor by it |
| `algorithm` | How values are encrypted; see [Supported formats](#supported-formats) |
| `key` | The key, in hex |
| `iv` | Optional. A fixed IV (or GCM nonce), in hex, when the application doesn't store one with each value |
| `padding` | Optional, for `aes-cbc`: `pkcs7` (the default), `spaces` or `zeros`; see [Supported formats](#supported-formats) |

Key in Base64? `echo '<base64 key>' | base64 -d | xxd -p -c 256` prints it in hex.

Set `MB_ENCRYPTION_SECRET_KEY` so Metabase encrypts the keys in its application database.

Saving connects and checks the decryptors (and rules, if any), so a typo or a key of the wrong size shows up right away.

### 4. Query

In a native query, alias an encrypted column `decrypt_<decryptor>_<name>` and it comes back decrypted, as text:

```sql
SELECT id, ssn AS decrypt_pii_ssn, pan AS decrypt_legacy_pan FROM customers
```

Matching is case-insensitive. A `decrypt_` alias naming an unknown decryptor fails the query instead of quietly showing
ciphertext. Other columns work as with the regular SQL Server driver.

The prefix stays in the column name, so Metabase shows **Decrypt Pii Ssn**, and questions built on the query refer to
the column by it. To show a nicer name, change only the displayed one:

* **In one question:** click the column's gear icon and change its title.
* **Everywhere:** turn the query into a model and set the column's display name (e.g. "SSN") in the model's metadata.
  Questions built on the model use that name, and query-builder questions on the model are decrypted too.

## Writing rules

In query-builder questions, Metabase writes the SQL itself, with the table's real column names, so there's no alias to
prefix. Rules, in **Encrypted columns**, cover that: "for this table and column, use that decryptor". They're optional;
if everyone queries through native SQL or models built from it, you don't need them.

```xml
<rule pattern="customers.ssn" decryptor="pii"/>
<rule pattern="dbo.cards.pan" decryptor="legacy"/>
<rule pattern="/_enc$/"       decryptor="pii"/>
```

| Attribute | |
|---|---|
| `pattern` | Which result columns to decrypt, either `[schema.][table.]column` or `/regex/` (below) |
| `decryptor` | A decryptor's name from **Decryptors** |

One `<rule>` element per rule. The first matching rule wins, and a `decrypt_` alias wins over any rule.

* `[schema.][table.]column` is matched case-insensitively against the result column's name and label. A Metabase join
  column labelled `Customers__ssn` also matches `ssn`.
* `/regex/` is searched for in the result column's label (its alias), case-insensitively.

> **SQL Server doesn't report which table a result column came from**, and it reports aliases as column names. So
> `customers.ssn` matches *any* result column named `ssn`, in every table. Keep rules for distinctive column names, and
> use `decrypt_` aliases for the rest.

## Supported formats

| `algorithm` (dashes optional) | Stored value | With an `iv` |
|---|---|---|
| `aes-gcm`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm` | `nonce(12) ‖ ciphertext ‖ tag(16)` | `ciphertext ‖ tag(16)` |
| `aes-cbc`, `aes-128-cbc`, `aes-192-cbc`, `aes-256-cbc` | `iv(16) ‖ ciphertext`, PKCS#7 padding | `ciphertext` |

Instead of PKCS#7, CBC plaintext can be padded to whole blocks with:

* `padding="spaces"`: spaces. Whitespace is trimmed from both ends after decrypting.
* `padding="zeros"`: zero bytes, as PHP's `mcrypt` and .NET's `PaddingMode.Zeros` do. Trailing zero bytes are
  removed after decrypting.

Encrypted with an all-zero IV? Give the decryptor `iv="00000000000000000000000000000000"`. A key size in the name is
checked against the key. Binary columns hold the stored value as raw bytes, text columns as hex (optionally
`0x`-prefixed) or Base64. The plaintext must be UTF-8.

Need another format? Open an issue.

## Good to know

* **Decryption happens after SQL Server returns the rows.** Filters, sorting, grouping and joins on an encrypted
  column run in the database, on ciphertext. Displaying values works; `WHERE ssn = '123-45-6789'` doesn't.
* **Plaintext reaches whatever Metabase stores.** That includes sampled filter values (set encrypted fields to *Search
  box* or *Plain input box*, or turn off value scanning), cached results, downloads and subscriptions. Anyone who can
  query this database sees plaintext, so a common setup keeps a regular SQL Server connection for most people and gives
  a restricted group access to the decrypting one.
* **Values that don't decrypt** show why, e.g. `[can't decrypt: wrong key or algorithm, or not encrypted (…)]`, in
  `decrypt_` columns. Columns picked by rules show them as stored instead (binary as `0x…` hex), because a rule can also
  match plain-text columns of the same name in other tables. Either way they're logged at debug level, without the
  value. NULL stays NULL.

## Building from source

Needs JDK 21+ and Maven:

```bash
mvn verify
```

The plugin is `metabase-sqlserver/target/sqlserver-decrypt.metabase-driver.jar`.

## License

[AGPL-3.0](LICENSE)
