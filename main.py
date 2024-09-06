import os
import argparse
import jwt
from cryptography.hazmat.primitives import serialization
import requests
import time
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
import logging
from dotenv import load_dotenv

# Suppress the warnings from urllib3
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Setting log file and format

log_dir = os.path.abspath(os.path.expanduser("~/logs_okta-group-vcenter"))

os.makedirs(log_dir, exist_ok=True)

# log_file = os.path.join(log_dir, "last-" + datetime.today().strftime("%A").lower() + ".log")

log_file = os.path.join(log_dir, datetime.today().strftime("%Y%m%d_%H%M%S") + ".log")

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO,
    filename=log_file,
    encoding="utf-8",
)

# Setting constant
load_dotenv()

VCSA_APIGROUPS = "usergroup/t/CUSTOMER/scim/v2/Groups"
VCSA_APIUSERS = "usergroup/t/CUSTOMER/scim/v2/Users"
VCSA_BEARER_TOKENS = os.getenv("VCSA_BEARER_TOKENS")
VCSA_HOSTS = os.getenv("VCSA_HOSTS")
OKTA_HOST = os.getenv("OKTA_HOST")
OKTA_CLIENTID = os.getenv("OKTA_CLIENTID")

tokens_list = VCSA_BEARER_TOKENS.split(",")
hosts_list = VCSA_HOSTS.split(",")

global vcsa_host
global vcsa_bearer_token
global vcsa_headers


class UserNotFoundException(Exception):
    pass


class GroupNotFoundException(Exception):
    pass


# Console print and log saving in one go
def print_and_log(text, level="info"):
    print(f"{text}")
    if level.lower() == "info":
        logging.info(f"{text}")
    elif level.lower() == "error":
        logging.error(f"{text}")
    elif level.lower() == "warning":
        logging.warning(f"{text}")
    else:
        return


# Post call
def post(url, headers, json_data={}) -> None:
    try:
        logging.info(f"POST - url: {url}")
        # logging.info(f"POST - url: {url} - headers: {headers} - body: {json_data}")
        response = requests.post(url, headers, json=json_data, verify=False)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        # handle errors
        print_and_log(f"Error posting data from url {url}: {e}", "error")
        raise e


# Delete call
def delete(url, headers) -> None:
    try:
        logging.info(f"DELETE - url: {url}")
        response = requests.delete(url, headers=headers, verify=False)
        response.raise_for_status()
    except requests.RequestException as e:
        # handle errors
        print_and_log(f"Error posting data from url {url}: {e}", "error")
        raise e


# Get call
def get(url, headers={}):
    try:
        logging.info(f"GET - url: {url}")
        # logging.info(f"GET - url: {url} - headers: {headers}")
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        # handle errors
        print_and_log(f"Error getting data from url {url}: {e}", "error")
        raise e


# Patch call
def patch(url, headers, json_data={}):
    try:
        logging.info(f"PATCH - url: {url}")
        # logging.info(f"PATCH - url: {url} - body: {json_data}")
        response = requests.patch(url, headers, json=json_data, verify=False)
        response.raise_for_status()
    except requests.RequestException as e:
        # handle errors
        print_and_log(f"Error posting data from url {url}: {e}", "error")
        raise e


# Create new user and add it to the group
def create_vcsa_user(row, groupName) -> None:
    print_and_log(f"Start creating user {row['username']} in {vcsa_host}")
    json_data = {
        "emails": [{"value": row["username"]}],
        "name": {
            "familyName": row["user_last_name"],
            "givenName": row["user_first_name"],
        },
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:ws1b:2.0:User",
        ],
        "userName": row["username"],
        "externalId": row["user_id"],
    }

    try:
        # logging.info(f"POST - url: https://{vcsa_host}/{VCSA_APIUSERS} - headers: {vcsa_headers} - body: {json_data}")
        logging.info(f"POST - url: https://{vcsa_host}/{VCSA_APIUSERS}")
        requests.post(
            f"https://{vcsa_host}/{VCSA_APIUSERS}",
            headers=vcsa_headers,
            json=json_data,
            verify=False,
        )
        print(f"User '{row['username']}' successfully created!")
    except requests.RequestException as e:
        print(f"Error creating user '{row['username']}'")
        print_and_log(
            f"Error posting data from url https://{vcsa_host}/{VCSA_APIUSERS}: {e}",
            "error",
        )
        return

    add_vcsa_member_group(row, groupName)


# Create the vcsa group
def create_vcsa_group(groupName) -> None:
    json_data = {"displayName": groupName, "schemas": ["urn:scim:schemas:core:1.0"]}
    try:
        logging.info(f"POST - url: https://{vcsa_host}/{VCSA_APIUSERS}")
        # logging.info(f"POST - url: https://{vcsa_host}/{VCSA_APIUSERS} - headers: {vcsa_headers} - body: {json_data}")
        requests.post(
            f"https://{vcsa_host}/{VCSA_APIGROUPS}",
            headers=vcsa_headers,
            json=json_data,
            verify=False,
        )
        print_and_log(f"Group {groupName} succesfully created in {vcsa_host}!")
        print_and_log(
            "To ensure the group has vCenter permissions you need to add it to a vCenter Group of which you can assign permissions to actually allow you to take actions.",
            "warning",
        )
    except requests.RequestException as e:
        print_and_log(
            f"Error posting data from url https://{vcsa_host}/{VCSA_APIUSERS}: {e}",
            "error",
        )
        return


# Delete the vcsa user by id
def delete_vcsa_user(row) -> None:
    print_and_log(f"Start deleting user {row['username']}")
    try:
        userId = get_vcsa_user_id(row["username"])
        print(f"userid to delete: {userId}")
        try:
            delete(
                f"https://{vcsa_host}/{VCSA_APIUSERS}/{userId}", headers=vcsa_headers
            )
            print(f"User '{row['username']}' successfully deleted!")
        except requests.RequestException:
            return
    except UserNotFoundException as e:
        print(e)


# Return the vcsa user id
def get_vcsa_user_id(userName) -> None:
    try:
        response = get(f"https://{vcsa_host}/{VCSA_APIUSERS}", headers=vcsa_headers)
        users = response.json()
        for user in users["Resources"]:
            if user["userName"] == userName:
                return user["id"]
        raise UserNotFoundException
    except requests.RequestException:
        return
    except UserNotFoundException:
        print(f"User {userName} not found in {vcsa_host}")


# Return the vcsa group id
def get_vcsa_group_id(groupName) -> None:

    try:
        response = get(f"https://{vcsa_host}/{VCSA_APIGROUPS}", vcsa_headers)
        groups = response.json()
        for group in groups["Resources"]:
            if group["displayName"] == groupName:
                return group["id"]
        raise GroupNotFoundException
    except requests.RequestException:
        return
    except GroupNotFoundException:
        print(f"Group {groupName} not found in {vcsa_host}")


# Remove user from group by ids
def remove_group_member(row):
    print_and_log(
        f"Start removing user {row['username']} from group {row['groupName']}"
    )
    try:
        userId = get_vcsa_user_id(row["username"])
        groupId = get_vcsa_group_id(row["groupName"])
        json_data = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "remove", "path": "members", "value": [{"value": userId}]}
            ],
        }
        try:
            patch(f"https://{vcsa_host}/{VCSA_APIGROUPS}/{groupId}", json_data)
            print(
                f"User '{row['username']}' successfully removed from group '{row['groupName']}'"
            )
        except requests.RequestException:
            return
    except UserNotFoundException as e:
        print(e)
    except GroupNotFoundException as e:
        print(e)


# Delete the group by id
def delete_vcsa_group(groupName):
    try:
        groupId = get_vcsa_group_id(groupName)
        try:
            delete(
                f"https://{vcsa_host}/{VCSA_APIGROUPS}/{groupId}", headers=vcsa_headers
            )
            print_and_log(f"Group '{groupName}' successfully deleted in {vcsa_host}")
        except requests.RequestException:
            return
    except GroupNotFoundException as e:
        print(e)


# Add user to group by ids
def add_vcsa_member_group(row, groupName):
    print_and_log(f"Start adding member {row['username']} to group {groupName}")
    try:
        userId = get_vcsa_user_id(row["username"])
        groupId = get_vcsa_group_id(groupName)

        json_data = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                {"op": "add", "path": "members", "value": [{"value": userId}]}
            ],
        }

        if groupId is None or userId is None:
            print(
                f"Skip adding member {row['username']} to group {groupName} in {vcsa_host}"
            )
        else:
            try:
                logging.info(
                    f"PATCH - url: https://{vcsa_host}/{VCSA_APIGROUPS}/{groupId}"
                )
                response = requests.patch(
                    f"https://{vcsa_host}/{VCSA_APIGROUPS}/{groupId}",
                    headers=vcsa_headers,
                    json=json_data,
                    verify=False,
                )
                response.raise_for_status()
            except requests.RequestException as e:
                # handle errors
                print_and_log(
                    f"Error patching data from url https://{vcsa_host}/{VCSA_APIGROUPS}/{groupId} : {e}",
                    "error",
                )
                raise e

    except UserNotFoundException as e:
        print(e)
    except GroupNotFoundException as e:
        print(e)


def get_okta_bearer_token():

    # print("\nStart get_okta_bearer_token")

    jwt_token = get_okta_jwt()

    response = post(
        f"https://{OKTA_HOST}/oauth2/v1/token",
        {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "grant_type": "client_credentials",
            "scope": "okta.groups.read",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": f"{jwt_token}",
        },
    )

    return response.json().get("access_token")


def get_okta_jwt():

    # print("\nStart get_okta_jwt")

    # Load private key
    with open(os.getenv("PRIVATE_KEY_ABSOLUTE_PATH"), "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    # create the jwt
    token = jwt.encode(
        {
            "aud": f"https://{OKTA_HOST}/oauth2/v1/token",
            "iss": f"{OKTA_CLIENTID}",
            "sub": f"{OKTA_CLIENTID}",
            "exp": int(time.time() + 300),
        },
        private_key,
        algorithm="RS256",
    )

    # print(token)
    return token


def get_okta_members_of_group(groupName):

    print_and_log("Start getting users from Okta group")

    okta_users = []

    okta_bearer_token = get_okta_bearer_token()

    okta_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Bearer " + f"{okta_bearer_token}",
    }

    # Get href to retrieve members
    response = get(
        f"https://{OKTA_HOST}/api/v1/groups?q={groupName}",
        okta_headers,
    )

    # Get from href to retrieve members
    if len(response.json()) > 0:
        print(response.json())
        members = get(response.json()[0]["_links"]["users"]["href"], okta_headers)

        for user in members.json():
            user_id = user.get("id")
            username = user.get("profile", {}).get("login")
            user_first_name = user.get("profile", {}).get("firstName")
            user_last_name = user.get("profile", {}).get("lastName")
            okta_users.append(
                {
                    "username": username,
                    "user_id": user_id,
                    "user_first_name": user_first_name,
                    "user_last_name": user_last_name,
                }
            )

        if len(okta_users) > 0:
            print("\nPrint members of the Okta group " + f"{groupName}" + ": ")
            for user in okta_users:
                print(user)
        else:
            print(f"No user found in Okta group {groupName}")

    else:
        print(f"Group {groupName} not found in {OKTA_HOST}")

    return okta_users


def get_vcenter_members_of_group(groupName):

    print_and_log("Starting get users from vCenter group")

    vcsa_users = []

    groupId = get_vcsa_group_id(groupName)

    if groupId is not None:
        response = get(
            f"https://{vcsa_host}/{VCSA_APIUSERS}",
            {
                "Authorization": "Bearer " + vcsa_bearer_token,
                "Content-Type": "application/scim+json",
            },
        )
        if len(response.json()) > 0:
            for user in response.json()["Resources"]:
                for group in user["groups"]:
                    if group["value"] == groupId:
                        user_id = user.get("externalId")
                        username = user.get("userName")
                        user_first_name = user.get("name", {}).get("givenName")
                        user_last_name = user.get("name", {}).get("familyName")
                        vcsa_users.append(
                            {
                                "username": username,
                                "user_id": user_id,
                                "user_first_name": user_first_name,
                                "user_last_name": user_last_name,
                            }
                        )

            if len(vcsa_users) > 0:
                print(
                    "\nPrinting members of the vCenter group " + f"{groupName}" + ": "
                )
                for user in vcsa_users:
                    print(user)
            else:
                print(f"No user found in vCenter group {groupName}")

        else:
            print(f"No user found in vCenter group {groupName}")

    else:
        exit

    return vcsa_users


def test_okta_connection():

    print("Start connecting to Okta")
    okta_bearer_token = get_okta_bearer_token()
    if okta_bearer_token:
        print_and_log(f"Successfully connected to Okta!")


def test_vcenter_connection():

    print(f"Start connecting to vCenter {vcsa_host}")
    response = get(f"https://{vcsa_host}/{VCSA_APIGROUPS}", vcsa_headers)
    if response:
        print_and_log("Successfully connected to vCenter!")


# Main function
def main():

    logging.info(f"----- START SCRIPT -----")

    global vcsa_host
    global vcsa_bearer_token
    global vcsa_headers

    description = "This Python script handles some basics user and group operations into a vCenter from Okta source. It interacts with Okta and vCenter through the Okta API and through the vCenter SCIM API, using HTTP requests exclusively for managing user and group operations. The admitted operations are 3:\n\t1.Syncing group members from Okta to vCenter - create or delete user where is necessary;\n\t2.Create vCenter group;\n\t3.Delete vCenter group;\n\t4.Test the connection to Okta or vCenter;\n\nMultiple groups are admitted, see usage section.\nAdditionally, the script logs events and errors for monitoring purposes."

    parser = argparse.ArgumentParser(
        description=description, formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--sync",
        type=str,
        help="sync the group from Okta to vCenter, specify more than one group if needed",
        metavar="groupName",
        nargs="+",
    )
    group.add_argument(
        "--create",
        type=str,
        help="create the vCenter group",
        metavar="groupName",
        nargs="+",
    )
    group.add_argument(
        "--delete",
        type=str,
        help="delete the vCenter group",
        metavar="groupName",
        nargs="+",
    )
    group.add_argument(
        "--test",
        type=str,
        help="test the connection to Okta or vCenter ",
        metavar="object",
    )

    args = parser.parse_args()
    print("args:", args)
    if args.sync:
        action = "1"
        groupNames = args.sync
    elif args.create:
        action = "2"
        groupNames = args.create
    elif args.delete:
        action = "3"
        groupNames = args.delete
    elif args.test:
        action = "4"
        object_to_test = args.test
    else:
        print(
            "Select an option: \n\t1. Sync \n\t2. Create group \n\t3. Delete group \n\t4. Test connection"
        )
        action = input()
        if action == "4":
            print("Insert the object to test (okta | vcenter):")
            object_to_test = input()
        else:
            print("Insert the group (or groups) name:")
            groupNames = input()

    if action == "1" and groupNames:
        for groupName in groupNames:
            okta_users = get_okta_members_of_group(groupName)
            for token, host in zip(tokens_list, hosts_list):
                vcsa_host = host
                vcsa_bearer_token = token
                vcsa_headers = {
                    "Authorization": "Bearer " + vcsa_bearer_token,
                    "Content-Type": "application/scim+json",
                }

                # sync group
                logging.info(
                    f"Start syncing group " + groupName + " in vCenter " + vcsa_host
                )

                vcsa_users = get_vcenter_members_of_group(groupName)

                users_to_add = []

                users_to_delete = []

                # 1. Get users to create
                if okta_users:
                    vcenter_user_ids = {user["user_id"] for user in vcsa_users}
                    for user in okta_users:
                        if user["user_id"] not in vcenter_user_ids:
                            users_to_add.append(user)

                    if users_to_add:
                        for user in users_to_add:
                            print_and_log(f"Start adding user: {user} to vCenter group")
                            if get_vcsa_user_id(user["username"]) is None:
                                create_vcsa_user(user, groupName)
                            else:
                                print(f"The user already exists in {vcsa_host}")
                                add_vcsa_member_group(user, groupName)

                # 2. Get users to delete
                if vcsa_users:
                    okta_user_ids = {user["user_id"] for user in okta_users}
                    for user in vcsa_users:
                        if user["user_id"] not in okta_user_ids:
                            users_to_delete.append(user)

                    if users_to_delete:
                        for user in users_to_delete:
                            print_and_log(
                                f"Start deleting user: {user} from vCenter group"
                            )
                            delete_vcsa_user(user)

                if not users_to_delete and not users_to_add:
                    print_and_log("No operations needed, the groups are already synced")

                logging.info(
                    f"Group {groupName} succesfully synced in vCenter {vcsa_host}"
                )
    elif action == "2" and groupNames:
        for groupName in groupNames:
            for token, host in zip(tokens_list, hosts_list):

                vcsa_host = host
                vcsa_bearer_token = token
                vcsa_headers = {
                    "Authorization": "Bearer " + vcsa_bearer_token,
                    "Content-Type": "application/scim+json",
                }
                # create group
                print_and_log(f"Start creating group {groupName} in {vcsa_host}")
                create_vcsa_group(groupName)

    elif action == "3" and groupNames:
        for groupName in groupNames:
            for token, host in zip(tokens_list, hosts_list):

                vcsa_host = host
                vcsa_bearer_token = token
                vcsa_headers = {
                    "Authorization": "Bearer " + vcsa_bearer_token,
                    "Content-Type": "application/scim+json",
                }
                # delete group
                print_and_log(f"Start deleting group {groupName} in {vcsa_host}")
                delete_vcsa_group(groupName)

    elif action == "4" and object_to_test != "":
        # test connection
        logging.info(f"Start testing connection to " + object_to_test)
        if object_to_test.lower().strip() == "okta":
            test_okta_connection()
        elif object_to_test.lower().strip() == "vcenter":
            for token, host in zip(tokens_list, hosts_list):

                vcsa_host = host
                vcsa_bearer_token = token
                vcsa_headers = {
                    "Authorization": "Bearer " + vcsa_bearer_token,
                    "Content-Type": "application/scim+json",
                }
                test_vcenter_connection()
    else:
        print_and_log(
            "Invalid choice, please enter '1' to sync an existing group,'2' to creating a group, '3' to deleting a group or '4' to test a connection"
        )

    logging.info(f"----- END SCRIPT -----")


if __name__ == "__main__":
    main()
