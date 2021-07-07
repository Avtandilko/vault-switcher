import hvac
import os
import sys
import logging


def read_vault_token_from_file(token_file_path):
    with open(token_file_path, "r") as file:
        data = file.readline().rstrip()
    return data


def check_path_exists(client, mount_point, path):
    try:
        data = client.secrets.kv.v2.read_secret_version(
            mount_point=mount_point,
            path=path,
        )
        log.info("Path %s/%s exists", mount_point, path)
        return True

    except hvac.exceptions.InvalidPath:
        log.info("Path %s/%s doesn't exists", mount_point, path)
        return False


def duplicate_path_with_new_name(client, mount_point, source_path, dest_path):
    read_response = client.secrets.kv.read_secret_version(
        mount_point=mount_point, path=source_path
    )
    client.secrets.kv.v2.create_or_update_secret(
        mount_point=mount_point,
        path=dest_path,
        secret=dict(read_response["data"]["data"]),
        cas=0,
    )
    log.info(
        "Path %s/%s duplicated with the name %s/%s",
        mount_point,
        source_path,
        mount_point,
        dest_path,
    )


def duplicate_variables_list(
    client, mount_point, source_path, dest_path, variables_list
):
    read_response = client.secrets.kv.read_secret_version(
        mount_point=mount_point, path=source_path
    )

    if variables_list:
        log.info(
            "The following variables well be duplicated: %s",
            format(", ".join(map(str, variables_list))),
        )
    else:
        log.info("Variables not specified")

    read_response = client.secrets.kv.read_secret_version(
        mount_point=mount_point,
        path=source_path,
    )

    variables_to_add = {}

    for secret in variables_list:
        if secret in read_response["data"]["data"].keys():
            log.info(
                "Pre-adding a variable %s to the new secret %s/%s",
                secret,
                mount_point,
                dest_path,
            )
            variables_to_add[secret] = read_response["data"]["data"].get(secret)
        else:
            log.info(
                "There is no predefined variable %s in %s/%s. Skip copy",
                secret,
                mount_point,
                source_path,
            )

        if variables_to_add:
            for secret in variables_to_add:
                log.info(
                    "Add variables %s to the new secret %s/%s",
                    secret,
                    mount_point,
                    dest_path,
                )

        client.secrets.kv.v2.create_or_update_secret(
            mount_point=mount_point,
            path=dest_path,
            secret=dict(variables_to_add),
        )


if __name__ == "__main__":

    VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    VAULT_TOKEN_FILE = os.getenv("VAULT_TOKEN_FILE")
    VAULT_TOKEN = os.getenv("VAULT_TOKEN")
    VAULT_MOUNT_POINT = os.getenv("VAULT_MOUNT_POINT", "secrets")
    VAULT_SOURCE_PATH = os.getenv("VAULT_SOURCE_PATH")
    VAULT_DEST_PATH = os.getenv("VAULT_DEST_PATH")

    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}',
    )
    log = logging.getLogger()

    if VAULT_TOKEN is not None:
        pass
    elif VAULT_TOKEN_FILE is not None:
        VAULT_TOKEN = read_vault_token_from_file(VAULT_TOKEN_FILE)
    else:
        log.error("Set VAULT_TOKEN of VAULT_TOKEN_FILE variables")
        quit()

    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

    log.info("Authenticated in vault: %s", client.is_authenticated())

    if check_path_exists(client, VAULT_MOUNT_POINT, VAULT_SOURCE_PATH):
        if check_path_exists(client, VAULT_MOUNT_POINT, VAULT_DEST_PATH):
            pass
        else:
            duplicate_path_with_new_name(
                client, VAULT_MOUNT_POINT, VAULT_SOURCE_PATH, VAULT_DEST_PATH
            )
    else:
        log.info("Unknown behavior")

    duplicate_variables_list(
        client,
        VAULT_MOUNT_POINT,
        VAULT_SOURCE_PATH,
        VAULT_DEST_PATH,
        [""],
    )
