'''
Create JIRA issue

Input: enriched_alert_input.json
'''

import ast
import base64
import gzip
import json
import os
import urllib

import boto3
import numpy as np
import pandas as pd
import requests
from botocore.exceptions import ClientError
from requests.auth import HTTPBasicAuth

JIRA_URL = os.getenv("jira_url")

JIRA_PROJECT_KEY = os.getenv("jira_project_key")

JIRA_USERNAME = os.getenv("jira_username")

JIRA_API_TOKEN = os.getenv("jira_api_token")

JIRA_LOOKUP_OBJECT = os.getenv("jira_lookup_object")

CLUSTER_OR_FLOW = os.getenv("cluster_or_flow").lower()

EVENT_THRESHOLD = int(os.getenv("event_threshold"))

missing_variables = []
if JIRA_URL is None:
    missing_variables.append("jira_url")
if JIRA_PROJECT_KEY is None:
    missing_variables.append("jira_project_key")
if JIRA_USERNAME is None:
    missing_variables.append("jira_username")
if JIRA_API_TOKEN is None:
    missing_variables.append("jira_api_token")
if JIRA_LOOKUP_OBJECT is None:
    missing_variables.append("jira_lookup_object")
if CLUSTER_OR_FLOW is None:
    missing_variables.append("cluster_or_flow")
if EVENT_THRESHOLD is None:
    missing_variables.append("event_threshold")

if missing_variables:
    raise ValueError(f"Please enter environment variable(s): {missing_variables}")

if CLUSTER_OR_FLOW not in ["flow", "cluster"]:
    raise ValueError(f"Valid values for 'cluster_or_flow' environemnt variable are 'flow', 'cluster'. Entered value is: '{CLUSTER_OR_FLOW}'")

S3_CLIENT = boto3.client("s3")

SCRATCH_DIR = "scratch"

TEMP_CLUSTER_TICKET_OUTPUT = "/tmp/cluster_ticket_output.json"
TEMP_FLOW_TICKET_OUTPUT = "/tmp/flow_ticket_output.json"

TEMP_INPUT_FILENAME = f"/tmp/{CLUSTER_OR_FLOW}_ticket_output.json"

TEMP_CLUSTER_OR_FLOW_FILENAME = f"/tmp/{CLUSTER_OR_FLOW}.txt"

TEMP_JIRA_LOOKUP_FILE = "/tmp/issues.csv"


def lambda_handler(event, context):
    '''
    Entrypoint from the trigger setup from lambda
    Args:
        event: Event triggered
        context: Context of the lambda function
    '''
    global TEMP_INPUT_FILENAME
    global TEMP_CLUSTER_OR_FLOW_FILENAME
    global SCRATCH_DIR
    global TEMP_JIRA_LOOKUP_FILE
    global JIRA_LOOKUP_OBJECT
    global CLUSTER_OR_FLOW
    global S3_CLIENT

    func = "lambda_handler"

    # compressed_payload = base64.b64decode(event['awslogs']['data'])
    # decompressed_payload = gzip.decompress(compressed_payload)

    # log_event = json.loads(decompressed_payload)
    # message = log_event['logEvents'][0]["message"]

    # print(f"Log Message: {message}")

    # message_dict = json.loads(message)

    # bucket = message_dict["bucket"]
    bucket = event["Records"][0]["s3"]["bucket"]["name"]
    try:
        # input_filename = message_dict["key"]
        input_filename = urllib.parse.unquote_plus(event["Records"][0]["s3"]["object"]["key"], encoding="utf-8")

        unique_id = input_filename.split("/")[-2]
        if input_filename.endswith("flow_ticket_output.json"):
            CLUSTER_OR_FLOW = "flow"
            return
        else:
            CLUSTER_OR_FLOW = "cluster"

        TEMP_INPUT_FILENAME = f"/tmp/{CLUSTER_OR_FLOW}_ticket_output.json"

        TEMP_CLUSTER_OR_FLOW_FILENAME = f"/tmp/{CLUSTER_OR_FLOW}.txt"

        print(f"{func}: Download input file: {bucket}/{input_filename}")
        try:
            S3_CLIENT.download_file(bucket, input_filename, TEMP_INPUT_FILENAME)
            print(f"{func}: Input file download completed")

        except Exception as e:
            print(f"{func}: Failed to download input file")
            raise e

        if CLUSTER_OR_FLOW == "flow":
            try:
                print(f"{func}: Download intermediate file")
                cluster_ticket_output_file = f"{SCRATCH_DIR}/intermediate/{unique_id}/cluster_ticket_output.json"
                S3_CLIENT.download_file(bucket, cluster_ticket_output_file, TEMP_CLUSTER_TICKET_OUTPUT)
            except Exception as e:
                print(f"{func}: Failed to download file from S3: {bucket}/{cluster_ticket_output_file}")
                raise e

        fetch_or_create_jira_lookup_file(bucket)

        print(f"{func}: Start creation of JIRA issue")
        if CLUSTER_OR_FLOW == "cluster":
            process_cluster_to_jira(bucket, unique_id)
        else:
            process_flow_to_jira(bucket, unique_id)

        print(f"{func}: JIRA issues created")

        try:
            S3_CLIENT.upload_file(TEMP_JIRA_LOOKUP_FILE, bucket, JIRA_LOOKUP_OBJECT)

        except Exception as e:
            print(f"{func}: Failed to upload to S3: {bucket}/{JIRA_LOOKUP_OBJECT}")
            raise e
    except Exception as ex:
        print(f"{func}: Exception occurred while running lambda function. Uploading error file to S3.")
        error_message = f"Error occurred in lambda function: {context.function_name}. More details can be found in CloudWatch Logs for this lambda function. The exception message is: {ex}"
        upload_error_to_s3(bucket, error_message)
        raise ex


def process_cluster_to_jira(bucket, unique_id):
    '''
    Fetch older JIRA issue id if created for cluster. Create or update issue.
    Args:
        bucket: Bucket name
        unique_id: unique id corresponding to the last chunk of current input file
    Returns:
        None
    '''
    global TEMP_INPUT_FILENAME
    global CLUSTER_OR_FLOW
    global TEMP_JIRA_LOOKUP_FILE
    global EVENT_THRESHOLD
    global TEMP_CLUSTER_TICKET_OUTPUT

    func = "process_cluster_to_jira"

    cluster_ticket_output_df = pd.read_json(TEMP_CLUSTER_TICKET_OUTPUT, lines=True)

    if f"{CLUSTER_OR_FLOW}_id" not in cluster_ticket_output_df.columns:
        print(f"{func}: There is no {CLUSTER_OR_FLOW}_id detected for this chunk input. No JIRA issue to create")
        exit(0)

    unique_cluster_id_list_in_cluster_ticket_output = np.sort(cluster_ticket_output_df[f"{CLUSTER_OR_FLOW}_id"].dropna().unique())

    if len(cluster_ticket_output_df) < 1:
        print(f"{func}: No {CLUSTER_OR_FLOW} detected. Skip creation of JIRA issue.")
        return

    print(f"{func}: Number of {CLUSTER_OR_FLOW}: {len(unique_cluster_id_list_in_cluster_ticket_output)}")

    jira_lookup_df = pd.read_csv(TEMP_JIRA_LOOKUP_FILE, converters={'unique_id': convert_to_list})

    # fetch data for created JIRA
    filtered_jira_lookup_df = jira_lookup_df[jira_lookup_df["cluster_id"].isin(unique_cluster_id_list_in_cluster_ticket_output)]
    if len(filtered_jira_lookup_df) > 0:
        print(f"{func}: Jira lookup file has previously processed unique ids")
        processed_unique_id_list = filtered_jira_lookup_df["unique_id"].sum()
        processed_unique_id_set = set(processed_unique_id_list)

        print(f"{func}: List of unique_id to fetch data: {processed_unique_id_set}")

        fetch_data_for_all_batches(bucket, processed_unique_id_set)

    get_processed_unique_id_cluster_ticket_output_df = cluster_ticket_output_df.merge(jira_lookup_df[["cluster_id", "unique_id", "issue_key"]],
                                                                                      how="left",
                                                                                      left_on="cluster_id", right_on="cluster_id")

    created_issue_keys = []

    for _, row_cluster_ticket_output in get_processed_unique_id_cluster_ticket_output_df.iterrows():
        print(f"{func}: Evaluating for {CLUSTER_OR_FLOW}: {row_cluster_ticket_output['cluster_id']}")

        print(row_cluster_ticket_output.to_dict())
        cluster_id = row_cluster_ticket_output['cluster_id']

        print(f"{func}: Check if JIRA issue already created.")

        previously_created_issue_key = None
        previously_processed_unique_id = None

        involved_events = row_cluster_ticket_output["involved_events"]

        if isinstance(row_cluster_ticket_output["unique_id"], list):
            if not np.isnan(row_cluster_ticket_output["issue_key"]):
                previously_created_issue_key = row_cluster_ticket_output["issue_key"]
            previously_processed_unique_id = row_cluster_ticket_output["unique_id"]

            # get all involved event from previously processed unique ids
            for processed_unique_id in previously_processed_unique_id:
                processed_filename = f"/tmp/{processed_unique_id}/cluster_ticket_output.json"
                processed_df = pd.read_json(processed_filename)
                filtered_processed_df = processed_df[processed_df["cluster_id"] == cluster_id]
                involved_events.extend(filtered_processed_df.iloc[0]["involved_events"])

        involved_events_df = pd.DataFrame(involved_events)

        print(f"Number of alerts: {len(involved_events_df)}")

        if len(involved_events_df) < EVENT_THRESHOLD:
            print(f"{func}: Skip creating JIRA ticket as the number of alerts is less than threhold: {EVENT_THRESHOLD}")
            if not np.isnan(row_cluster_ticket_output["issue_key"]):
                created_issue_keys.append((row_cluster_ticket_output["issue_key"], cluster_id))
            else:
                created_issue_keys.append((np.nan, cluster_id))
            continue

        issue_key = create_jira(bucket, unique_id, cluster_id, involved_events_df,
                                involved_clusters=[cluster_id],
                                previously_created_issue_key=previously_created_issue_key,
                                previously_processed_unique_id=previously_processed_unique_id)

        created_issue_keys.append((issue_key, cluster_id))

    update_local_jira_lookup_table(created_issue_keys, unique_id)


def process_flow_to_jira(bucket, unique_id):
    '''
    Fetch older JIRA issue id if created for flow. Create or update issue.
    Args:
        bucket: Bucket name
        unique_id: unique id corresponding to the last chunk of current input file
    Returns:
        None
    '''
    global TEMP_INPUT_FILENAME
    global CLUSTER_OR_FLOW
    global TEMP_JIRA_LOOKUP_FILE
    global EVENT_THRESHOLD
    global TEMP_FLOW_TICKET_OUTPUT
    global TEMP_CLUSTER_TICKET_OUTPUT

    func = "process_flow_to_jira"

    flow_ticket_output_df = pd.read_json(TEMP_FLOW_TICKET_OUTPUT, lines=True)
    cluster_ticket_output_df = pd.read_json(TEMP_CLUSTER_TICKET_OUTPUT, lines=True)

    if f"{CLUSTER_OR_FLOW}_id" not in flow_ticket_output_df.columns:
        print(f"{func}: There is no {CLUSTER_OR_FLOW}_id detected for this chunk input. No JIRA issue to create")
        exit(0)

    unique_flow_id_list_in_flow_ticket_output = np.sort(flow_ticket_output_df[f"{CLUSTER_OR_FLOW}_id"].dropna().unique())

    if len(flow_ticket_output_df) < 1:
        print(f"{func}: No {CLUSTER_OR_FLOW} detected. Skip creation of JIRA issue.")
        return

    print(f"{func}: Number of {CLUSTER_OR_FLOW}: {len(unique_flow_id_list_in_flow_ticket_output)}")

    jira_lookup_df = pd.read_csv(TEMP_JIRA_LOOKUP_FILE, converters={'unique_id': convert_to_list})

    # fetch data for created JIRA
    filtered_jira_lookup_df = jira_lookup_df[jira_lookup_df["flow_id"].isin(unique_flow_id_list_in_flow_ticket_output)]

    if len(filtered_jira_lookup_df) > 0:
        processed_unique_id_list = filtered_jira_lookup_df["unique_id"].sum()
        processed_unique_id_set = set(processed_unique_id_list)
        fetch_data_for_all_batches(bucket, processed_unique_id_set)

    get_processed_unique_id_flow_ticket_output_df = flow_ticket_output_df.merge(jira_lookup_df[["flow_id", "unique_id", "issue_key"]],
                                                                                   how="left",
                                                                                   left_on="flow_id", right_on="flow_id")

    created_issue_keys = []

    for _, row_flow_ticket_output in get_processed_unique_id_flow_ticket_output_df.iterrows():
        print(f"{func}: Evaluating for {CLUSTER_OR_FLOW}: {row_flow_ticket_output['flow_id']}")

        flow_id = row_flow_ticket_output['flow_id']

        print(f"{func}: Check if JIRA issue already created.")

        previously_created_issue_key = None
        previously_processed_unique_id = None

        filtered_cluster_ticket_output_df = \
            cluster_ticket_output_df[cluster_ticket_output_df["ticket_id"].isin(row_flow_ticket_output["cluster_ticket_ids"])]
        involved_events = filtered_cluster_ticket_output_df["involved_events"]

        involved_clusters = filtered_cluster_ticket_output_df["cluster_id"].apply(list)

        if isinstance(row_flow_ticket_output["unique_id"], list):
            if not np.isnan(row_flow_ticket_output["issue_key"]):
                previously_created_issue_key = row_flow_ticket_output["issue_key"]
            previously_processed_unique_id = row_flow_ticket_output["unique_id"]

            # get all involved event from previously processed unique ids
            for processed_unique_id in previously_processed_unique_id:
                flow_processed_filename = f"/tmp/{processed_unique_id}/flow_ticket_output.json"
                cluster_processed_filename = f"/tmp/{processed_unique_id}/cluster_ticket_output.json"

                flow_processed_df = pd.read_json(flow_processed_filename)
                filtered_flow_processed_df = flow_processed_df[flow_processed_df["flow_id"] == row_flow_ticket_output["flow_id"]]
                filtered_flow_processed_dict = filtered_flow_processed_df.iloc[0].to_dict()

                cluster_processed_df = pd.read_json(cluster_processed_filename)
                filtered_cluster_processed_df = \
                    cluster_processed_df[cluster_processed_df["ticket_id"].isin(filtered_flow_processed_dict["cluster_ticket_ids"])]

                involved_events.extend(filtered_cluster_processed_df.iloc[0]["involved_events"])
                processed_cluster_ids = filtered_cluster_processed_df["cluster_id"].apply(list)
                involved_clusters.extend(processed_cluster_ids)

        involved_events_df = pd.DataFrame(involved_events)
        involved_clusters = set(involved_clusters)

        print(f"Number of alerts: {len(involved_events_df)}")

        if len(involved_events_df) < EVENT_THRESHOLD:
            print(f"{func}: Skip creating JIRA ticket as the number of alerts is less than threhold: {EVENT_THRESHOLD}")
            if not np.isnan(row_flow_ticket_output["issue_key"]):
                created_issue_keys.append((row_flow_ticket_output["issue_key"], flow_id))
            else:
                created_issue_keys.append((np.nan, flow_id))
            continue

        issue_key = create_jira(bucket, unique_id, flow_id, involved_events_df,
                                involved_clusters=involved_clusters,
                                previously_created_issue_key=previously_created_issue_key,
                                previously_processed_unique_id=previously_processed_unique_id)

        created_issue_keys.append((issue_key, flow_id))

    update_local_jira_lookup_table(created_issue_keys, unique_id)


def create_jira(bucket, unique_id, cluster_or_flow_id, filter_alerts_on_cluster_or_flow_id: pd.DataFrame,
                involved_clusters, previously_created_issue_key=None, previously_processed_unique_id=None):
    '''
    Create summary and description for an elastic case. Create or update case
    Args:
        bucket: Bucket name
        unique_id: unique id corresponding to the last chunk of current input file
        cluster_or_flow_id: Cluster id or flow id
        filter_alerts_on_cluster_or_flow_id: Alerts filtered for a cluster or flow id
        involved_clusters: List of involved cluster ids
        previously_created_issue_key: JIRA issue key for the cluster or flow id that was already created
        previously_processed_unique_id: List of previously processed unique ids for cluster or flow
    Returns:
        issue_key: Issue key of the issue that is updated or created.
    '''
    global SCRATCH_DIR
    global TEMP_CLUSTER_OR_FLOW_FILENAME
    global CLUSTER_OR_FLOW

    func = "create_jira"

    involved_alerts = list(set(filter_alerts_on_cluster_or_flow_id["id"].to_list()))

    involved_tech = [tech for tech_list in filter_alerts_on_cluster_or_flow_id["tech"].to_list() for tech in tech_list]
    involved_tech = list(set(involved_tech))

    involved_tac = [f"TA{tac:04}" for tac_list in filter_alerts_on_cluster_or_flow_id["tac"].to_list() for tac in tac_list]
    involved_tac = list(set(involved_tac))

    involved_src_ip = filter_alerts_on_cluster_or_flow_id["src"].to_list()
    involved_dst_ip = filter_alerts_on_cluster_or_flow_id["dst"].to_list()

    invovled_entites = list(set(involved_src_ip).union(involved_dst_ip))

    first_timestamp = filter_alerts_on_cluster_or_flow_id["time"].min()
    last_timestamp = filter_alerts_on_cluster_or_flow_id["time"].max()

    timeframe = f"{first_timestamp} - {last_timestamp}"

    # other_attributes_list = [ast.literal_eval(str(obj)) for obj in filter_alerts_on_cluster_or_flow_id["other_attributes_dict"].to_list()]
    other_attributes_df = pd.DataFrame(filter_alerts_on_cluster_or_flow_id["other_attributes_dict"].to_list())

    priority_list = None
    mean_priority = None
    median_priority = None
    url = None

    if "priority" in other_attributes_df:
        priority_list = list(set(other_attributes_df["priority"].dropna().to_list()))
        if not priority_list:
            priority_list = None
        else:
            mean_priority = other_attributes_df["priority"].mean()
            median_priority = other_attributes_df["priority"].median()

    if "url" in other_attributes_df:
        url = list(set(other_attributes_df["url"].dropna().to_list()))
        if not url:
            url = None

    description_dict = {
        "Involved Input Alerts": involved_alerts,
        "Involved Clusters": involved_clusters,
        "Involved techniques": involved_tech,
        "Involved tactics": involved_tac,
        "Involved Entites and Identities": invovled_entites,
        "Timeframe": timeframe,
        "Priorities": priority_list,
        "Mean Priorities": mean_priority,
        "Median Priorities": median_priority,
        "URLs": url,
        "Path for JSON(s)": [unique_id]
    }

    if previously_processed_unique_id is not None:
        description_dict["Path for JSON(s)"] = previously_processed_unique_id + description_dict["Path for JSON(s)"]

    description_dict["Path for JSON(s)"] = \
        [f"s3://{bucket}/{SCRATCH_DIR}/intermediate/{id}/{CLUSTER_OR_FLOW}_ticket_output.json" for id in description_dict["Path for JSON(s)"]]

    description_text = []
    for k, v in description_dict.items():
        if v is not None:
            description_text.append(f"{k}: {v}")

    description_text = "\n".join(description_text)
    with open(TEMP_CLUSTER_OR_FLOW_FILENAME, "w") as f:
        f.writelines(description_text)

    print(f"{func}: Length of description text: {len(description_text)}")

    summary = f"{CLUSTER_OR_FLOW.upper()} {cluster_or_flow_id}"

    # If the description length exceeds the limit allowed on JIRA, then add it as attachment. Make JIRA description generic.
    description = "The description text for the issue is too long to be included in this section. Please read the attachment file 'description.txt' for more details."
    if len(description_text) <= 32500:
        description = description_text

    if previously_created_issue_key is None:
        print(f"{func}: Creating new issue")
        issue_key = api_create_issue(summary=summary, description=description)
    else:
        print(f"{func}: Updating issue: {previously_created_issue_key}")
        issue_key = api_update_issue(issue_key=previously_created_issue_key, summary=summary, description=description)

    # If the description length exceeds the limit allowed on JIRA, then add it as attachment.
    if len(description_text) > 32500:
        print(f"{func}: The description text is too large to be added to JIRA issue directly. Adding it as attachment")
        api_attachment(issue_key=issue_key, attached_filename="description.txt", temp_filename=TEMP_CLUSTER_OR_FLOW_FILENAME)

    attach_original_alerts_subset(issue_key, unique_id, filter_alerts_on_cluster_or_flow_id)

    return issue_key


def attach_original_alerts_subset(issue_key, unique_id, filter_alerts_on_cluster_or_flow_id: pd.DataFrame):
    '''
    Add an attachment of involved alerts to JIRA issue
    Args:
        issue_key: JIRA issue key to which the file should be attached
        unique_id: unique id corresponding to the last chunk of current input file
        filter_alerts_on_cluster_or_flow_id: Alerts filtered for a cluster or flow id
    '''

    temp_attach_input_filename = "/tmp/filtered_input.json"

    filter_alerts_on_cluster_or_flow_id.to_json(temp_attach_input_filename, orient="records")

    api_attachment(issue_key=issue_key, attached_filename=f"{unique_id}_input.json",
                   temp_filename=temp_attach_input_filename)


def fetch_data_for_all_batches(bucket, prev_unique_ids):
    '''
    Get ticket output for all previously processed unique ids
    Args:
        bucket: Bucket name
        prev_unique_ids: list of unique ids
    '''
    global CLUSTER_OR_FLOW
    global S3_CLIENT
    global SCRATCH_DIR
    func = "fetch_data_for_all_batches"

    for prev_unique_id in prev_unique_ids:
        os.makedirs(f"/tmp/{prev_unique_id}", exist_ok=True)

        path_to_cluster_ticket_output_file = f"{SCRATCH_DIR}/intermediate/{prev_unique_id}/cluster_ticket_output.json"
        temp_cluster_ticket_output_filename = f"/tmp/{prev_unique_id}/cluster_ticket_output.json"

        try:
            S3_CLIENT.download_file(bucket, path_to_cluster_ticket_output_file, temp_cluster_ticket_output_filename)
            print(f"{func}: Downloaded cluster_ticket_output file")
        except Exception as e:
            print(f"{func}: Failed to download file: {bucket}/{path_to_cluster_ticket_output_file}")
            raise e

        if CLUSTER_OR_FLOW == "flow":
            path_to_flow_ticket_output_file = f"{SCRATCH_DIR}/intermediate/{prev_unique_id}/flow_ticket_output.json"
            temp_flow_ticket_output_filename = f"/tmp/{prev_unique_id}/flow_ticket_output.json"

            try:
                S3_CLIENT.download_file(bucket, path_to_flow_ticket_output_file, temp_flow_ticket_output_filename)
                print(f"{func}: Downloaded flow_ticket_output file")
            except Exception as e:
                print(f"{func}: Failed to download file: {bucket}/{path_to_flow_ticket_output_file}")
                raise e


def update_local_jira_lookup_table(created_issue_keys, unique_id):
    '''
    Update local jira lookup table
    Args:
        created_issue_keys: list of issue ids created or updated
        unique_id: unique id corresponding to the last chunk of current input file
    '''
    global TEMP_JIRA_LOOKUP_FILE
    global CLUSTER_OR_FLOW

    jira_lookup_df = pd.read_csv(TEMP_JIRA_LOOKUP_FILE, converters={'unique_id': convert_to_list})
    rows = []
    for issue_key, cluster_or_flow in created_issue_keys:
        jira_lookup_issue_filtered_df = jira_lookup_df[jira_lookup_df["issue_key"] == issue_key]

        row = {
            "issue_key": issue_key,
            "flow_id": None,
            "cluster_id": None,
            "unique_id": [unique_id],
            f"{CLUSTER_OR_FLOW}_id": cluster_or_flow,
        }
        if len(jira_lookup_issue_filtered_df):
            prev_row = jira_lookup_issue_filtered_df.iloc[0].to_dict()
            row["unique_id"] = prev_row["unique_id"] + row["unique_id"]

            jira_lookup_df = jira_lookup_df[jira_lookup_df["issue_key"] != issue_key]

        rows.append(row)

    temp_update_df = pd.DataFrame(rows)
    jira_lookup_df = pd.concat([jira_lookup_df, temp_update_df])
    jira_lookup_df.drop_duplicates(f"{CLUSTER_OR_FLOW}_id", keep="last", inplace=True)

    jira_lookup_df.to_csv(TEMP_JIRA_LOOKUP_FILE, index=False)


def fetch_or_create_jira_lookup_file(bucket):
    '''
    Download jira lookup file if already exists on S3 or create jira lookup file
    Args:
        bucket: Bucket name
    '''
    global JIRA_LOOKUP_OBJECT
    global TEMP_JIRA_LOOKUP_FILE
    global S3_CLIENT

    func = "fetch_or_create_jira_lookup_file"
    try:
        print(
            f"{func}: Checking if jira lookup file exists on S3 path {bucket}/{JIRA_LOOKUP_OBJECT}")

        S3_CLIENT.head_object(Bucket=bucket, Key=JIRA_LOOKUP_OBJECT)

    except ClientError as e:
        if e.response['Error']['Code'] != '404':
            raise e

        print(f"{func}: Jira lookup file does not exist on S3. Create empty table")

        jira_lookup_df = pd.DataFrame(columns=["issue_key", "flow_id", "cluster_id", "unique_id"])
        jira_lookup_df.to_csv(TEMP_JIRA_LOOKUP_FILE, index=False)

        print(f"{func}: Empty table created")
    else:
        try:
            print(f"{func}: Download available jira lookup file from S3")

            S3_CLIENT.download_file(bucket, JIRA_LOOKUP_OBJECT, TEMP_JIRA_LOOKUP_FILE)

            print(f"{func}: Download completed")
        except Exception as e:
            print(f"{func}: Failed to download lookup table from S3: {bucket}/{JIRA_LOOKUP_OBJECT}")
            raise e


def api_attachment(issue_key, attached_filename, temp_filename):
    '''
    API call to attach a file to JIRA issue
    Args:
        issue_key: Issue key to which the file should be attached
        attached_filename: File name of the attachment
        temp_filename: Local filename to attach
    '''
    global JIRA_URL
    global JIRA_USERNAME
    global JIRA_API_TOKEN

    func = "api_attachment"

    attach_url = f"{JIRA_URL}/rest/api/2/issue/{issue_key}/attachments"
    headers = {
        "X-Atlassian-Token": "no-check"
    }
    files = {
        'file': (attached_filename, open(temp_filename, 'rb'), 'application/json')
    }

    try:
        attach_response = requests.post(
            attach_url,
            headers=headers,
            files=files,
            auth=HTTPBasicAuth(JIRA_USERNAME, JIRA_API_TOKEN),
            timeout=10
        )
        attach_response.raise_for_status()
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        print("Failed to attach file due to network error")
        raise e
    except requests.exceptions.RequestException as e:
        print(f"Issue created, but failed to attach file: {attach_response.json()}")
        raise e

    print(f"{func}: Issue created and file attached successfully. Issue key: {issue_key}")


def api_create_issue(summary, description):
    '''
    API call to create JIRA issue
    Args:
        summary: Title of the JIRA issue
        description: Description of the JIRA issue
    Returns:
        issue_key: Issue key created
    '''
    global JIRA_PROJECT_KEY
    global JIRA_URL
    global JIRA_USERNAME
    global JIRA_API_TOKEN

    func = "api_create_issue"
    issue_data = {
        "fields": {
            "project": {
                "key": JIRA_PROJECT_KEY
            },
            "summary": summary,
            "description": description,
            "issuetype": {
                "name": "Task"
            }
        }
    }

    try:
        issue_response = requests.post(
            f"{JIRA_URL}/rest/api/2/issue",
            data=json.dumps(issue_data),
            headers={
                "Content-Type": "application/json"
            },
            auth=HTTPBasicAuth(JIRA_USERNAME, JIRA_API_TOKEN),
            timeout=10
        )
        issue_response.raise_for_status()
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        print("Failed to create issue due to network error")
        raise e
    except requests.exceptions.RequestException as e:
        print(f"Failed to create issue: {issue_response.json()}")
        raise e

    issue_key = issue_response.json()['key']

    print(f"{func}: Issue created successfully. Issue key: {issue_key}")

    return issue_key


def api_update_issue(issue_key, summary, description):
    '''
    Fetch JIRA issue and status. Update or create issue based on issue status.
    Args:
        issue_key: Issue key to check status
        summary: Title of the JIRA issue
        description: Description of the JIRA issue
    Returns:
        issue_key: issue key updated or created
    '''
    global JIRA_URL
    global JIRA_USERNAME
    global JIRA_API_TOKEN

    func = "api_update_issue"

    issue_url = f"{JIRA_URL}/rest/api/2/issue/{issue_key}"

    try:
        response = requests.get(
            issue_url,
            headers={'Content-Type': 'application/json'},
            auth=HTTPBasicAuth(JIRA_USERNAME, JIRA_API_TOKEN),
            timeout=10
        )
        response.raise_for_status()
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        print("Failed to fetch issue due to network error")
        raise e
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch issue: {response.json()}")
        raise e

    issue_details = response.json()
    issue_status = issue_details['fields']['status']['name']

    print(f"{func}: Issue status: {issue_status}")

    update_issue_if_current_status = ['Open', 'To Do', 'In Progress']

    if issue_status in update_issue_if_current_status:
        # Update the issue description
        print(f"{func}: Updating issue description")
        update_url = f"{JIRA_URL}/rest/api/2/issue/{issue_key}"
        update_data = {
            'fields': {
                'description': description
            }
        }

        try:
            update_response = requests.put(
                update_url,
                data=json.dumps(update_data),
                headers={'Content-Type': 'application/json'},
                auth=HTTPBasicAuth(JIRA_USERNAME, JIRA_API_TOKEN),
                timeout=10
            )
            update_response.raise_for_status()
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            print("Failed to update issue due to network error")
            raise e
        except requests.exceptions.RequestException as e:
            print(f"Failed to update issue: {update_response.json()}")
            raise e

        return issue_key
    else:
        print(f"{func}: Create new issue as the issue is not in status {update_issue_if_current_status}")
        new_issue_key = api_create_issue(summary, description)
        api_link_issue(issue_key, new_issue_key)
        return new_issue_key


def api_link_issue(existing_issue_key, new_issue_key, link_type="Relates"):
    '''
    Link JIRA issue to another
    Args:
        existing_issue_key: Issue key of inward issue for the link type
        new_issue_key: Issue key of outward issue for the link type
        link_type: Type of link
    '''
    global JIRA_URL
    global JIRA_USERNAME
    global JIRA_API_TOKEN
    link_url = f"{JIRA_URL}/rest/api/2/issueLink"
    link_data = {
        "type": {
            "name": link_type
        },
        "inwardIssue": {
            "key": existing_issue_key
        },
        "outwardIssue": {
            "key": new_issue_key
        }
    }

    auth = HTTPBasicAuth(JIRA_USERNAME, JIRA_API_TOKEN)
    headers = {
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            link_url,
            data=json.dumps(link_data),
            headers=headers,
            auth=auth,
            timeout=10
        )
        response.raise_for_status()
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        print("Failed to link issue due to network error")
        raise e
    except requests.exceptions.RequestException as e:
        print(f"Failed to link issue: {response.json()}")
        raise e


def upload_error_to_s3(bucket, error_message):
    '''
    Upload error message to S3
    Args:
        error_message: The error message to upload
        unique_id: Unique ID for identifying the error log
    '''
    global S3_CLIENT
    error_log_key = "output/error_log.txt"
    try:
        S3_CLIENT.put_object(Bucket=bucket, Key=error_log_key, Body=error_message)
        print(f"Uploaded error log to s3://{bucket}/{error_log_key}")
    except Exception as e:
        print(f"Failed to upload error log to S3. Error: {str(e)}")


def convert_to_list(value):
    return ast.literal_eval(value)
