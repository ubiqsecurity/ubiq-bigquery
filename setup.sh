# Optional: set $verbose_deploy to see queries being run.

[[ -z "${gcloud_multi_region}" ]] && read -p "Google Cloud Multi-Region (us, eu): " gcloud_multi_region
[[ -z "${gcloud_region}" ]] && read -p "Google Cloud Region (us-west2, asia-south1): " gcloud_region
[[ -z "${gcloud_project_id}" ]] && read -p "Google Cloud Project ID (eg. isometric-dog-01587): " gcloud_project_id
[[ -z "${gcloud_bucket_name}" ]] && read -p "Google Cloud Storage Bucket Name: " gcloud_bucket_name
[[ -z "${bq_dataset}" ]] && read -p "BigQuery Dataset Name: " bq_dataset

connection_id="${gcloud_multi_region}.ubiq_bigquery"

# Deploy Key Fetch
(cd  ubiq-broker/ubiq_fetch_dataset_and_structured_key && gcloud functions deploy ubiq_fetch_dataset_and_structured_key --gen2 --runtime=nodejs20 --source=. --entry-point=ubiq_fetch_dataset_and_structured_key --trigger-http)
# Deploy Decrypt Dataset Keys
(cd  ubiq-broker/ubiq_decrypt_dataset_keys && gcloud functions deploy ubiq_decrypt_dataset_keys --gen2 --runtime=nodejs20 --source=. --entry-point=ubiq_decrypt_dataset_keys --trigger-http)
# Deploy Submit Events
(cd  ubiq-broker/ubiq_submit_events && gcloud functions deploy ubiq_submit_events --gen2 --runtime=nodejs20 --source=. --entry-point=ubiq_submit_events --trigger-http)

# Create the connection in BigQuery
bq mk --connection --location=$gcloud_region --project_id=$gcloud_project_id \
    --connection_type=CLOUD_RESOURCE ubiq_bigquery

# verify
bq show --connection $gcloud_project_id.$connection_id

# Prompt user about setting up IAM Permissions.
echo "Connection will need to be set up with IAM Access before continuing."
echo "You will need the serviceAccountId (***@***.gserviceaccount.com) from the properties from above."
echo "https://cloud.google.com/bigquery/docs/remote-functions#grant_permission_on_function"

read -n 1 -s -r -p "Press any key to continue"

# Deploy Remote Functions to BQ

base_url="https://$gcloud_region-$gcloud_project_id.cloudfunctions.net"

fetch_url="$base_url/ubiq_fetch_dataset_and_structured_key"
fetch_function="CREATE OR REPLACE FUNCTION \`$gcloud_project_id.$bq_dataset.ubiq_fetch_dataset_and_structured_key\`(dataset_names STRING, access_key STRING, secret_signing_key STRING) RETURNS JSON
REMOTE WITH CONNECTION \`$gcloud_project_id.$connection_id\`
OPTIONS (
  endpoint = '$fetch_url'
);"


decrypt_key_url="$base_url/ubiq_decrypt_dataset_keys"
decrypt_key_function="CREATE OR REPLACE FUNCTION \`$gcloud_project_id.$bq_dataset.ubiq_decrypt_dataset_keys\`(ubiq_cache JSON, secret_crypto_signing_key STRING) RETURNS JSON
REMOTE WITH CONNECTION \`$gcloud_project_id.$connection_id\`
OPTIONS (
  endpoint = '$decrypt_key_url'
);"

submit_events_url="$base_url/ubiq_submit_events"
submit_events_function="CREATE OR REPLACE FUNCTION \`$gcloud_project_id.$bq_dataset.ubiq_submit_events_remote\`(access_key STRING, secret_signing_key STRING, events STRING) RETURNS JSON
REMOTE WITH CONNECTION \`$gcloud_project_id.$connection_id\`
OPTIONS (
  endpoint = '$submit_events_url'
);"


process_events_function="CREATE OR REPLACE FUNCTION \`$gcloud_project_id.$bq_dataset.ubiq_process_events\`(access_key STRING, json_events STRING)
RETURNS STRING
LANGUAGE js
AS r\"\"\"
    VERSION = '1.0.0'
    const conditions = ['ubiq_encrypt', 'ubiq_decrypt']
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
            if(type == 'ubiq_encrypt'){
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
\"\"\";"

[[ -z "${verbose_deploy}" ]] && echo $fetch_function
bq query --nouse_legacy_sql $fetch_function

[[ -z "${verbose_deploy}" ]] && echo $decrypt_key_function;
bq query --nouse_legacy_sql $decrypt_key_function

[[ -z "${verbose_deploy}" ]] && echo $submit_events_function
bq query --nouse_legacy_sql $submit_events_function

[[ -z "${verbose_deploy}" ]] && echo $process_events_function
bq query --nouse_legacy_sql $process_events_function

# Upload Library to Bucket
gcloud storage cp ubiq-udf/* gs://$gcloud_bucket_name


# Initialize Functions on BQ

begin_session_sql="CREATE OR REPLACE PROCEDURE $bq_dataset.ubiq_begin_session(dataset_names STRING, access_key STRING, secret_signing_key STRING, secret_crypto_access_key STRING)
BEGIN 
  CREATE TEMP TABLE ubiq_cache(cache JSON)
  AS
  SELECT \`$gcloud_project_id.$bq_dataset.ubiq_decrypt_dataset_keys\`(
    (SELECT \`$gcloud_project_id.$bq_dataset.ubiq_fetch_dataset_and_structured_key\`(dataset_names, access_key, secret_signing_key)),
    secret_crypto_access_key
  );
END;"

encrypt_function_sql="CREATE OR REPLACE FUNCTION \`$bq_dataset.ubiq_encrypt\`(plainText STRING, datasetName STRING, ubiqDatasetKeyCache JSON)
RETURNS STRING
LANGUAGE js
OPTIONS (
  library= ['gs://$gcloud_bucket_name/arrayUtil.js', 'gs://$gcloud_bucket_name/base64-binary.js', 'gs://$gcloud_bucket_name/BigInteger.js','gs://$gcloud_bucket_name/Bn.js','gs://$gcloud_bucket_name/errorMessages.js','gs://$gcloud_bucket_name/FFX.js','gs://$gcloud_bucket_name/FF1.js','gs://$gcloud_bucket_name/structuredEncryptDecrypt.js','gs://$gcloud_bucket_name/strUtils.js','gs://$gcloud_bucket_name/aes-dst-exp.js']
)
AS r\"\"\"
  return Encrypt({plainText, datasetName, ubiqDatasetKeyCache})
\"\"\";"

encrypt_for_search_sql="CREATE OR REPLACE FUNCTION \`$bq_dataset.ubiq_encrypt_for_search\`(plainText STRING, datasetName STRING, ubiqDatasetKeyCache JSON)
RETURNS ARRAY<STRING>
LANGUAGE js
OPTIONS (
  library= ['gs://$gcloud_bucket_name/arrayUtil.js', 'gs://$gcloud_bucket_name/base64-binary.js', 'gs://$gcloud_bucket_name/BigInteger.js','gs://$gcloud_bucket_name/Bn.js','gs://$gcloud_bucket_name/errorMessages.js','gs://$gcloud_bucket_name/FFX.js','gs://$gcloud_bucket_name/FF1.js','gs://$gcloud_bucket_name/structuredEncryptDecrypt.js','gs://$gcloud_bucket_name/strUtils.js','gs://$gcloud_bucket_name/aes-dst-exp.js']
)
AS r\"\"\"
  return EncryptForSearch({plainText, datasetName, ubiqDatasetKeyCache})
\"\"\";"

decrypt_function_sql="CREATE OR REPLACE FUNCTION \`$bq_dataset.ubiq_decrypt\`(cipherText STRING, datasetName STRING, ubiqDatasetKeyCache JSON)
RETURNS STRING
LANGUAGE js
OPTIONS (
  library= ['gs://$gcloud_bucket_name/arrayUtil.js', 'gs://$gcloud_bucket_name/base64-binary.js', 'gs://$gcloud_bucket_name/BigInteger.js','gs://$gcloud_bucket_name/Bn.js','gs://$gcloud_bucket_name/errorMessages.js','gs://$gcloud_bucket_name/FFX.js','gs://$gcloud_bucket_name/FF1.js','gs://$gcloud_bucket_name/structuredEncryptDecrypt.js','gs://$gcloud_bucket_name/strUtils.js','gs://$gcloud_bucket_name/aes-dst-exp.js']
)
AS r\"\"\"
  return Decrypt({cipherText, datasetName, ubiqDatasetKeyCache})
\"\"\";"

submit_events_sql="CREATE OR REPLACE FUNCTION \`$gcloud_project_id.$bq_dataset.ubiq_submit_events\`(access_key STRING, secret_signing_key STRING)
AS(
    (SELECT \`$gcloud_project_id.$bq_dataset.ubiq_submit_events_remote\`(access_key, secret_signing_key, (SELECT
        \`$gcloud_project_id.$bq_dataset.ubiq_process_events\`(access_key,
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
                    OR query LIKE '%ubiq_decrypt%')
                    AND (query NOT LIKE '%INFORMATION_SCHEMA%')
                    AND (statement_type NOT IN ('CREATE_FUNCTION', 'SCRIPT'))
                    AND error_result IS NULL
                    AND job_type = 'QUERY'
                    AND creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
                    )
                SELECT
                CONCAT('[', STRING_AGG(TO_JSON_STRING(t), ','), ']')
                FROM
                EventData AS t)
            )
        )
    )
));";

[[ -z "${verbose_deploy}" ]] && echo $begin_session_sql
bq query --nouse_legacy_sql $begin_session_sql

[[ -z "${verbose_deploy}" ]] && echo $encrypt_function_sql
bq query --nouse_legacy_sql $encrypt_function_sql

[[ -z "${verbose_deploy}" ]] && echo $encrypt_for_search_sql
bq query --nouse_legacy_sql $encrypt_for_search_sql

[[ -z "${verbose_deploy}" ]] && echo $decrypt_function_sql
bq query --nouse_legacy_sql $decrypt_function_sql

[[ -z "${verbose_deploy}" ]] && echo $submit_events_sql
bq query --nouse_legacy_sql $submit_events_sql