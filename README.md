
# Ubiq Encryption in Google BigQuery

The Ubiq Security BigQuery library provides a convenient interaction with the Ubiq Security Platform API from applications written to interact with the Google Cloud BigQuery environment. Included is a pre-defined set of functions and classes that will provide a simple interface to encrypt and decrypt data.
This repository contains BigQuery user-defined functions (UDFs) to enable UDF-based encryption and decryption operations within BigQuery data platform. It leverages a combination of Google Cloud Functions and library files stored in Google Cloud Storage.

# Configuration

A shell script (`setup.sh`) has been provided to perform these steps for you. Ensure you have [Google Cloud CLI](https://cloud.google.com/sdk/docs/quickstart) installed first and authenticated. You will need to provide information for it to function properly.

If you wish to deploy manually, or encounter a problem, use the steps below.

## Deploy Broker Functions

In order to work with the Ubiq API, external functions must be set up within Google Cloud. This will create three functions:
1. Fetch your dataset definitions & appropriate keys
2. Decrypt your keys to be used within the BigQuery environment.
3. Submit event information to ubiq for metrics purposes

```shell
(cd  ubiq-broker/ubiq_fetch_dataset_and_structured_key && gcloud functions deploy ubiq_fetch_dataset_and_structured_key --gen2 --runtime=nodejs20 --source=. --entry-point=ubiq_fetch_dataset_and_structured_key --trigger-http)
(cd  ubiq-broker/ubiq_decrypt_dataset_keys && gcloud functions deploy ubiq_fetch_dataset_and_structured_key --gen2 --runtime=nodejs20 --source=. --entry-point=ubiq_decrypt_dataset_keys --trigger-http)
(cd  ubiq-broker/ubiq_submit_events && gcloud functions deploy ubiq_submit_events --gen2 --runtime=nodejs20 --source=. --entry-point=ubiq_submit_events --trigger-http)
```

## Create Remote Function Connection

Google's documents can guide you through this step. You will need to tell BigQuery how & where to access the deployed Cloud Functions.

Google's documentation can be found here: [Remote Functions - Create a Connection](https://cloud.google.com/bigquery/docs/remote-functions#create_a_connection)

## Create Remote Function in BigQuery
Run the following sql statements in BigQuery. You will need to swap `PROJECT_ID`, `BQ_DATASET`, `CONNECTION_ID`, and the endpoint url to the appropriate values for your gcloud project.

```sql
CREATE FUNCTION `PROJECT_ID.BQ_DATASET.ubiq_fetch_dataset_and_structured_key`(dataset_names STRING, access_key_id STRING, secret_signing_key STRING) RETURNS JSON
REMOTE WITH CONNECTION `CONNECTION_ID`
OPTIONS (
  endpoint = 'URL TO FFS_AND_FPE_KEY FUNCTION'
);

CREATE FUNCTION `PROJECT_ID.BQ_DATASET.ubiq_decrypt_dataset_keys`(ubiq_cache JSON, secret_crypto_signing_key STRING) RETURNS JSON
REMOTE WITH CONNECTION `CONNECTION_ID`
OPTIONS (
  endpoint = 'URL TO DECRYPT_DATASET_KEYS FUNCTION'
);

CREATE FUNCTION `PROJECT_ID.BQ_DATASET.ubiq_submit_events_remote`(ubiq_cache JSON, secret_crypto_signing_key STRING) RETURNS JSON
REMOTE WITH CONNECTION `CONNECTION_ID`
OPTIONS (
  endpoint = 'URL TO SUBMIT_EVENTS FUNCTION'
);
```

The url for the endpoints will probably look like `https://REGION-PROJECT_ID.cloudfunctions.net/<ubiq function name>`. You will need to modify this as appropriate. If you find yours does not match this, and you are having difficulties running the setup shell script, please contact Ubiq Support.

## Deploy the Ubiq UDF Library to a Google Storage Bucket

Upload the files in the `ubiq-udf` folder to a Google Storage bucket of your choosing.

Documentation can be found here: [Google Cloud Storage - Uploading an Object](https://cloud.google.com/storage/docs/uploading-objects#uploading-an-object)

Make sure to note down the name of the bucket you are uploading to. All files should be in the same location.

## Create the Ubiq Functions
This function intializes the ubiq session and pulls all data needed for you to begin encrypting or decrypting.

```sql
CREATE OR REPLACE PROCEDURE testing.ubiq_begin_session(dataset_names STRING, access_key STRING, secret_signing_key STRING, secret_crypto_access_key STRING)
BEGIN
  CREATE TEMP TABLE ubiq_cache(cache JSON)
  AS
  SELECT `PROJECT_ID.BQ_DATASET.ubiq_decrypt_dataset_keys`(
    (SELECT `PROJECT_ID.BQ_DATASET.ubiq_fetch_dataset_and_structured_key`(dataset_names, access_key, secret_signing_key)),
    secret_crypto_access_key
  );
END;
```

The following queries create the Encrypt and Decrypt functions using the libraries uploaded earlier. Replace `BUCKET_PATH` with the path you uploaded the files to in the previous step.

```sql
CREATE OR REPLACE FUNCTION `BQ_DATASET.ubiq_encrypt`(datasetName STRING, plainText STRING, ubiqDatasetKeyCache JSON)
RETURNS STRING
LANGUAGE js
OPTIONS (
  library= ['gs://BUCKET_PATH/arrayUtil.js','gs://BUCKET_PATH/BigInteger.js','gs://BUCKET_PATH/Bn.js','gs://BUCKET_PATH/errorMessages.js','gs://BUCKET_PATH/FFX.js','gs://BUCKET_PATH/FF1.js','gs://BUCKET_PATH/structuredEncryptDecrypt.js','gs://BUCKET_PATH/strUtils.js','gs://BUCKET_PATH/aes-dst-exp.js']
)
AS r"""
  return Encrypt({datasetName, plainText, ubiqDatasetKeyCache})
""";

CREATE OR REPLACE FUNCTION `BQ_DATASET.ubiq_encryptForSearch`(datasetName STRING, plainText STRING, ubiqDatasetKeyCache JSON)
RETURNS ARRAY<STRING>
LANGUAGE js
OPTIONS (
  library= ['gs://BUCKET_PATH/arrayUtil.js','gs://BUCKET_PATH/BigInteger.js','gs://BUCKET_PATH/Bn.js','gs://BUCKET_PATH/errorMessages.js','gs://BUCKET_PATH/FFX.js','gs://BUCKET_PATH/FF1.js','gs://BUCKET_PATH/structuredEncryptDecrypt.js','gs://BUCKET_PATH/strUtils.js','gs://BUCKET_PATH/aes-dst-exp.js']
)
AS r"""
  return EncryptForSearch({datasetName, plainText, ubiqDatasetKeyCache})
""";

CREATE OR REPLACE FUNCTION `BQ_DATASET.ubiq_decrypt`(datasetName STRING, cipherText STRING, ubiqDatasetKeyCache JSON)
RETURNS STRING
LANGUAGE js
OPTIONS (
  library= ['gs://BUCKET_PATH/arrayUtil.js','gs://BUCKET_PATH/BigInteger.js','gs://BUCKET_PATH/Bn.js','gs://BUCKET_PATH/errorMessages.js','gs://BUCKET_PATH/FFX.js','gs://BUCKET_PATH/FF1.js','gs://BUCKET_PATH/structuredEncryptDecrypt.js','gs://BUCKET_PATH/strUtils.js','gs://BUCKET_PATH/aes-dst-exp.js']
)
AS r"""
  return Decrypt({datasetName, cipherText, ubiqDatasetKeyCache})
""";

```

Finally, these functions are needed to process and submit events to Ubiq for metrics data. All transformation of data is done on the BigQuery server, so no sensitive data will be sent to Ubiq.

```sql

CREATE OR REPLACE FUNCTION PROJECT_ID.BQ_DATASET.ubiq_process_events(access_key STRING, json_events STRING)
RETURNS STRING
LANGUAGE js
AS r"""
    VERSION = '2.2.0'
    const conditions = ['ubiq_encrypt', 'ubiq_encrypt_for_search', 'ubiq_decrypt']
    const events = []

    const raw_events = JSON.parse(json_events);

    function eventsFromActions(input, action_type, job, records_written){
        Object.keys(input).forEach(dataset_name => {
            const count = input[dataset_name] * records_written
            events.push({
                api_key: access_key,
                dataset_name,
                dataset_group_name: null,
                dataset_type: 'structured',
                billing_action: action_type,
                count,
                key_number: null,
                product: 'ubiq-bigquery',
                product_version: VERSION,
                'user-agent': 'ubiq-bigquery/' + VERSION,
                api_version: 'V3',
                first_call_timestamp: job.start_time,
                last_call_timestamp: job.end_time,
                user_defined: {
                    session_id: job.session_info.session_id,
                    job_id: job.job_id
                }
            })
        })
    }

    raw_events.forEach(job => {
        const actions = {
            encrypt: {},
            decrypt: {}
        }
        const matches = [...job.query.matchAll(/(ubiq_decrypt|ubiq_encrypt)\([^\)]*, ?'([^\)]*)'/g)]
        matches.forEach(match => {
            const type = match[1]
            const dataset = match[2]
            if(type == 'ubiq_encrypt' || type == 'ubiq_encryptForSearch'){
                if(actions.encrypt[dataset]){
                    actions.encrypt[dataset] += 1
                } else {
                    actions.encrypt[dataset] = 1
                }
            } else {
                if(actions.decrypt[dataset]){
                    actions.decrypt[dataset] += 1
                } else {
                    actions.decrypt[dataset] = 1
                }
            }
        })
        const outputStage = job.job_stages.find(s => s.name.includes('Output'))
    
        const records_written = parseInt(outputStage?.records_written || 0)
        eventsFromActions(actions.encrypt, 'encrypt', job, records_written)
        eventsFromActions(actions.decrypt, 'decrypt', job, records_written)
    })
    return JSON.stringify(events)
""";

CREATE FUNCTION `PROJECT_ID.BQ_DATASET.ubiq_submit_events`(access_key STRING, secret_signing_key STRING)
AS(
    (SELECT `$PROJECT_ID.BQ_DATASET.ubiq_submit_events_remote`(access_key, secret_signing_key, (SELECT
        testing.ubiq_process_events(access_key,
            (WITH EventsData AS (
                SELECT
                    start_time,
                    end_time,
                    session_info,
                    job_id,
                    query,
                    job_stages
                FROM
                    region-us.INFORMATION_SCHEMA.JOBS_BY_USER
                WHERE
                    (query LIKE '%ubiq_encrypt%'
                    OR query LIKE '%ubiq_decrypt%'
                    OR query LIKE '%ubiq_encrypt_for_search%')
                    AND (query NOT LIKE '%INFORMATION_SCHEMA%')
                    AND (statement_type NOT IN ('CREATE_FUNCTION', 'SCRIPT'))
                    AND error_result IS NULL
                    AND job_type = 'QUERY'
                    AND creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
                    )
                SELECT
                CONCAT('[', STRING_AGG(TO_JSON_STRING(t), ','), ']')
                FROM
                EventsData AS t)
            )
        )
    )
));
```

# Encrypting and Decrypting

Before running any commands, you will need to start a session.

`dataset_names` is a list of dataset names associated with the key you wish to use, separated by commas (eg. `"ssn,email,alpha_num"`). The rest should come from your credentials.

```sql
SELECT `BQ_DATASET.ubiq_begin_session`(
    dataset_names,
    access_key,
    secret_signing_key,
    secret_crypto_access_key
);
```

> **Note:** This creates a *temporary* table named `ubiq_cache`. Temporary tables are used to ensure sensitive keys & data do not remain in your environment for an extended period and are removed when your session terminates. 
>
> In *BigQuery* Temporary tables only exist for the length of the query block being executed. (More information here: [Big Query - Introduction to Sessions](https://cloud.google.com/bigquery/docs/sessions-intro)) This means you will either have to execute this query and following encrypt/decrypt actions at the same time OR enable Session Mode in your query tab (if using the Console). Instructions for enabling Session Mode can be found here:
>
>[Big Query - Creating Sessions](https://cloud.google.com/bigquery/docs/sessions-create)
>
> It is **not** recommended to store the ubiq cache in a non-temporary table. This can be viewed by query users with access to your database at any time, and can make your data less secure. The data will also persist until you remember to remove it with a drop query. 
>
>Additionally, unlike other ubiq database integartion libraries (where you can call using only `ubiq_encrypt(data, dataset_name)`), you **will** need to include this `SELECT cache FROM ubiq_cache` in your query. BigQuery has a limtation where you cannot refer to temporary tables in functions.


To encrypt:
```sql
SELECT `BQ_DATASET.ubiq_encrypt`(
    dataset_name,
    plain_text,
    (SELECT cache FROM ubiq_cache)
);
```

To decrypt:
```sql
SELECT `BQ_DATASET.ubiq_decrypt`(
    dataset_name,
    cipher_text,
    (SELECT cache FROM ubiq_cache)
);
```

### Encrypt for Search

To Encrypt for Search:
```sql
SELECT `BQ_DATASET.ubiq_encrypt_for_search`(
    dataset_name,
    plain_text,
    (SELECT cache from ubiq_cache)
);
```
Encrypt For Search is a function set provided to search your database for a value that has been encrypted.

## Example Query Set
TODO: to run this you must enable session mode
```sql
CALL dataset.ubiq_begin_session("SSN", <access_key>, <secret_signing_key>, <secret_crypto_access_key>);

SELECT name, `dataset.ubiq_decrypt`('email', email, (SELECT cache from ubiq_cache)) as email, customer_id FROM customer_data;


INSERT INTO `dataset.customer_data` (customer_id, name, sensitive_field,) VALUES (
    1, 'Sam Watkins', `dataset.ubiq_encrypt`('alpha_num', <sensitive_data>, (SELECT cache from ubiq_cache))
);

SELECT `dataset.ubiq_submit_events`( <access_key>, <secret_signing_key>);
```

# IDP Authentication

Enterprise customers who use an IDP with Google Big Query can set up an alternate way to encrypt/decrypt data. Once users & datasets have been provisioned through your IDP, you can use a different method to authenticate and retrieve datasets and keys in BigQuery.

A shell script containing setup for relevant SQL & Broker functions has been included. See `idp_setup.sh`. Ensure you have [Google Cloud CLI](https://cloud.google.com/sdk/docs/quickstart) installed first and authenticated. You will need to provide information for it to function properly.

Please contact Ubiq Support for more detail.

**Secret Manager Values needed**
- **IDP Private Key** - To authenticate, a Public/Private keypair will need to be generated. This can either be made in IDP Settings as part of the Account Settings on the Ubiq Dashboard, or by contacting Ubiq Support and providing the Public Key. The Private key will be used to sign requests made to the Ubiq API. (Ubiq will use the Public key to verify.)

**ENV Variables needed**
- **IDP_CUSTOMER_ID** - Customer ID provided by Ubiq for SSO Authentication
- **IDP_PRIVATE_KEY_PATH** - Store the Private Key in Google Secrets Manager. Expose it to the cloud function as a volume. This should contain the path to access that volume/file.


### Mounting IDP Secret Key (Google Cloud)
Mounting the IDP Secret Key is more secure than just setting the key as an environment variable. Environment variables are set at startup, so any changes would require a redeploy. Setting as a volume ensures the latest value is always used. For more information, see [Google's documentation](https://cloud.google.com/run/docs/configuring/services/secrets).

1. Ensure you have the [Secret Manager API](https://console.cloud.google.com/security/secret-manager) enabled.
1. Create a new Secret
    - Name it something reasonable, eg. `idp_private_key`
    - Generate the IDP Key Pair from the Ubiq Dashboard. ( [Profile](https://dashboard-dev.ubiqsecurity.com/#/profile) => IDP Integration => Generate Keypair)
1. Go to CloudRun function settings (ubiq-idp-auth)
1. Edit & Deploy New Revision at the top
    1. Click Volumes tab
        1. Add new Volume
        1. Volume Type: Secret
        1. Choose a volume name, eg. `idp_private_key` and set Secret to the secret created in Step 2.
    1. Containers Tab -> Volume Mounts
        1. Select the volume made in the previous step
        1. Set the mount path ie `idp`
        1. Note the final mount path eg. `/idp/idp_private_key`
    1. Containers Tab -> Variables & Secrets
        1. IDP_CUSTOMER_ID - Customer ID provided by Ubiq
        1. IDP_PRIVATE_KEY_PATH - The mount path from the Volume Mounts step
1. Deploy



## Ubiq API Error Reference

Occasionally, you may encounter issues when interacting with the Ubiq API. 

| Status Code | Meaning | Solution |
|---|---|---|
| 400 | Bad Request | Check name of datasets and credentials are complete. |
| 401 | Authentication issue | Check you have the correct API keys, and it has access to the datasets you are using.  Check dataset name. |
| 426 | Upgrade Required | You are using an out of date version of the library, or are trying to use newer features not supported by the library you are using.  Update the library and try again.
| 429 | Rate Limited | You are performing operations too quickly. Either slow down, or contact support@ubiqsecurity.com to increase your limits. | 
| 500 | Internal Server Error | Something went wrong. Contact support if this persists.  | 
| 504 | Internal Error | Possible API key issue.  Check credentials or contact support.