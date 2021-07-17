import os
import sys
import hvac
import json
import logging
import argparse


def read_vault_token_from_file(token_file_path):
    with open(token_file_path, "r") as file:
        data = file.readline().rstrip()
    return data


def check_secret_exists(client, mount_point, path):
    try:
        client.secrets.kv.v2.read_secret_version(
            mount_point=mount_point,
            path=path,
        )
        log.info("Secret %s/%s exists", mount_point, path)
        return True

    except hvac.exceptions.InvalidPath:
        log.info("Secret %s/%s doesn't exists", mount_point, path)
        return False


def clone_secret(client, mount_point, source_secret, dest_secret):
    read_response = client.secrets.kv.read_secret_version(
        mount_point=mount_point, path=source_secret
    )
    client.secrets.kv.v2.create_or_update_secret(
        mount_point=mount_point,
        path=dest_secret,
        secret=dict(read_response["data"]["data"]),
        cas=0,
    )
    log.info(
        "Secret %s/%s copied with the name %s/%s",
        mount_point,
        source_secret,
        mount_point,
        dest_secret,
    )


def delete_secret(client, mount_point, secret_to_delete):
    client.secrets.kv.v2.delete_metadata_and_all_versions(
        mount_point=mount_point, path=secret_to_delete
    )
    log.info("Secret %s/%s deleted", mount_point, secret_to_delete)


def clone_variables_list(
    client, mount_point, source_secret, dest_secret, variables_list
):
    read_response = client.secrets.kv.read_secret_version(
        mount_point=mount_point, path=source_secret
    )

    if variables_list:
        log.info(
            "The following variables will be copied: %s",
            format(", ".join(map(str, variables_list))),
        )
    else:
        log.info("Variables not specified")

    read_response = client.secrets.kv.read_secret_version(
        mount_point=mount_point,
        path=source_secret,
    )

    variables_to_add = {}

    for secret in variables_list:
        if secret in read_response["data"]["data"].keys():
            log.info(
                "Pre-adding a variable %s to the new secret %s/%s",
                secret,
                mount_point,
                dest_secret,
            )
            variables_to_add[secret] = read_response["data"]["data"].get(
                secret
            )
        else:
            log.info(
                "There is no predefined variable %s in %s/%s. Skip copy",
                secret,
                mount_point,
                source_secret,
            )

    if variables_to_add:
        for secret in variables_to_add:
            log.info(
                "Add variable %s to the new secret %s/%s",
                secret,
                mount_point,
                dest_secret,
            )

    client.secrets.kv.v2.create_or_update_secret(
        mount_point=mount_point,
        path=dest_secret,
        secret=dict(variables_to_add),
    )


if __name__ == "__main__":

    # Set logging params

    LOGFORMAT = '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}'  # noqa

    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format=LOGFORMAT,
    )
    log = logging.getLogger()

    # Define environment variables
    VAULT_ADDR = os.getenv("VAULT_ADDR")
    VAULT_TOKEN_FILE = os.getenv("VAULT_TOKEN_FILE")
    VAULT_TOKEN = os.getenv("VAULT_TOKEN")
    VAULT_MOUNT_POINT = os.getenv("VAULT_MOUNT_POINT")
    VAULT_SOURCE_SECRET = os.getenv("VAULT_SOURCE_SECRET")
    VAULT_DEST_SECRET = os.getenv("VAULT_DEST_SECRET")
    VAULT_SECRET_TO_DELETE = os.getenv("VAULT_SECRET_TO_DELETE")
    VARIABLES_LIST = json.loads(os.getenv("VARIABLES_LIST", "[]"))

    # Checking variables used to connect to HashiCorp Vault
    if VAULT_TOKEN is None and VAULT_TOKEN_FILE is None:
        log.error("Set VAULT_TOKEN of VAULT_TOKEN_FILE variables")
        sys.exit()

    if VAULT_ADDR is None:
        log.error("Set VAULT_ADDR variable")
        sys.exit()

    # Using VAULT_TOKEN or read token from VAULT_TOKEN_FILE
    # if VAULT_TOKEN variable is not set
    if VAULT_TOKEN is not None:
        pass
    elif VAULT_TOKEN_FILE is not None:
        VAULT_TOKEN = read_vault_token_from_file(VAULT_TOKEN_FILE)

    # Connecting to Vault and check if authentication succeeded
    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)
    log.info("Authenticated in vault: %s", client.is_authenticated())

    # Defining command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--action",
        required=True,
        choices=["clone-secret", "clone-variables", "delete-secret"],
    )

    args = parser.parse_args()

    # Doing some actions according to command-line arguments
    if args.action == "clone-secret":

        # Checking required environment variables
        if VAULT_MOUNT_POINT is None:
            log.error("Set VAULT_MOUNT_POINT variable")
            sys.exit()

        if VAULT_SOURCE_SECRET is None:
            log.error("Set VAULT_SOURCE_SECRET variable")
            sys.exit()

        if VAULT_DEST_SECRET is None:
            log.error("Set VAULT_DEST_SECRET variable")
            sys.exit()

        # Checking for a destination secret to avoid overwriting it
        if check_secret_exists(client, VAULT_MOUNT_POINT, VAULT_DEST_SECRET):
            log.info(
                "The existing secret %s/%s will not be overwritten",
                VAULT_MOUNT_POINT,
                VAULT_DEST_SECRET,
            )
            sys.exit()

        # Checking for a source secret
        if not check_secret_exists(
            client, VAULT_MOUNT_POINT, VAULT_SOURCE_SECRET
        ):
            log.error(
                "Make sure the path %s/%s to the source secret is correct",
                VAULT_MOUNT_POINT,
                VAULT_SOURCE_SECRET,
            )
            sys.exit()

        # Cloning a secret if all checks passed
        clone_secret(
            client, VAULT_MOUNT_POINT, VAULT_SOURCE_SECRET, VAULT_DEST_SECRET
        )

    elif args.action == "clone-variables":

        # Checking required environment variables
        if VAULT_MOUNT_POINT is None:
            log.error("Set VAULT_MOUNT_POINT variable")
            sys.exit()

        if VAULT_SOURCE_SECRET is None:
            log.error("Set VAULT_SOURCE_SECRET variable")
            sys.exit()

        if VAULT_DEST_SECRET is None:
            log.error("Set VAULT_DEST_SECRET variable")
            sys.exit()

        if VARIABLES_LIST is None:
            log.error("Set VARIABLES_LIST variable")
            sys.exit()

        # Checking for a destination secret to avoid overwriting it
        if check_secret_exists(client, VAULT_MOUNT_POINT, VAULT_DEST_SECRET):
            log.info(
                "The existing secret %s/%s will not be overwritten",
                VAULT_MOUNT_POINT,
                VAULT_DEST_SECRET,
            )
            sys.exit()

        # Checking for a source secret
        if not check_secret_exists(
            client, VAULT_MOUNT_POINT, VAULT_SOURCE_SECRET
        ):
            log.error(
                "Make sure the path %s/%s to the source secret is correct",
                VAULT_MOUNT_POINT,
                VAULT_SOURCE_SECRET,
            )
            sys.exit()

        # Cloning a variables list if all checks passed
        clone_variables_list(
            client,
            VAULT_MOUNT_POINT,
            VAULT_SOURCE_SECRET,
            VAULT_DEST_SECRET,
            VARIABLES_LIST,
        )

    elif args.action == "delete-secret":

        # Checking required environment variables
        if VAULT_MOUNT_POINT is None:
            log.error("Set VAULT_MOUNT_POINT variable")
            sys.exit()

        if VAULT_SECRET_TO_DELETE is None:
            log.error("Set VAULT_SECRET_TO_DELETE variable")
            sys.exit()

        # Checking for a secret to be deleted
        if not check_secret_exists(
            client, VAULT_MOUNT_POINT, VAULT_SECRET_TO_DELETE
        ):
            log.error(
                "Make sure the path %s/%s to the secret to be deleted is correct",  # noqa
                VAULT_MOUNT_POINT,
                VAULT_SECRET_TO_DELETE,
            )
            sys.exit()

        delete_secret(client, VAULT_MOUNT_POINT, VAULT_SECRET_TO_DELETE)
