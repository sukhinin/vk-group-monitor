#!/usr/bin/python3

import os
import socket
import time

import requests


class VkError(Exception):
    """Generic VK API invocation error."""
    pass


class Vk:
    """Implements a subset of VK API.

    Attributes:
        api_version (str): supported VK API version
        access_token (str): VK access token
    Args:
        access_token (str): VK access token
    """

    def __init__(self, access_token):
        self.api_version = "5.52"
        self.access_token = access_token

    def get_group_managers_oneshot(self, group_id, offset=0):
        """Returns a list of group's managers starting from specified offset without any pagination.
        Pagination is supported by get_group_managers() method which in general should be preferred over this one.

        Note:
            This method results in a single HTTP call.
        Args:
            group_id (str): Group identifier.
            offset (int, optional): Starting offset in members list. Defaults to 0.
        Returns:
            A list of dictionaries where each item has `id` and `role` keys.
        """
        managers = []
        data = self.call("groups.getMembers", filter="managers", group_id=group_id, offset=str(offset))
        for item in data["items"]:
            managers.append({"id": str(item["id"]), "role": item["role"]})
        return managers

    def get_group_managers(self, group_id):
        """Returns a list of group's managers.

        Note:
            This method supports pagination and may result in more than one API call.
        Args:
            group_id (str): Group identifier.
        Returns:
            A list of dictionaries where each item has `id` and `role` keys.
        """
        managers = []
        while True:
            items = self.get_group_managers_oneshot(group_id, len(managers))
            if not items:
                break
            managers.extend(items)
        return managers

    def get_users_oneshot(self, user_ids):
        """Returns user details for up to 1000 user IDs. Unlimited number of entries can be obtained
        by calling get_users() method.

        Note:
            This method results in a single API call.
        Args:
            user_ids (iterable): A list of user IDs (strings). Limited to 1000 items.
        Returns:
            Dictionary of user details keyed by user ID. Each value in dictionary is a dictionary itself
            with a single `name` field.
        """
        users = {}
        data = self.call("users.get", user_ids=",".join(user_ids))
        for item in data:
            name = " ".join([item["last_name"], item["first_name"]])
            users[str(item["id"])] = {"name": name}
        return users

    def get_users(self, user_ids):
        """Returns a list of user details.

        Note:
            This method may result in more than one API call.
        Args:
            user_ids (iterable): A list of user IDs (strings).
        Returns:
            Dictionary of user details keyed by user ID. Each value in dictionary is a dictionary itself
            with a single `name` field.
        """
        users = {}
        for i in range(0, len(user_ids), 1000):
            user_ids_chunk = user_ids[i:i + 1000]
            users_chunk = self.get_users_oneshot(user_ids_chunk)
            users.update(users_chunk)
        return users

    def call(self, method, **kwargs):
        """ Calls the specified VK API method.

        Method name and arguments are used 'as is' without any processing or encoding.

        Note:
            Do not include `access_token` or `v` parameters in `**kwargs` as they're provided
            by method implementation.
        Args:
            method (str): Method name.
            **kwargs: Method arguments.
        Returns:
            Dictionary with the result of the API method invocation.
        """
        url = f"https://api.vk.com/method/{method}?v={self.api_version}&access_token={self.access_token}"
        for key in kwargs:
            url += "&" + key + "=" + kwargs[key]
        r = requests.get(url)
        r.raise_for_status()
        result = r.json()
        if "error" in result:
            raise VkError(result["error"]["error_msg"])
        return result["response"]


class Splunk:
    """Allows sending events to Splunk via TCP input.

    Attributes:
        sock: Network socket used to communicate with Splunk TCP endpoint.
    Args:
        address (str): Host and port of Splunk's TCP input.
    """

    def __init__(self, address):
        host, port = address.split(":", 2)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, int(port)))

    def __del__(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except OSError:
            pass

    def write_events_batch(self, events, **extra):
        """Writes a batch of events to Splunk.

        Note:
            Event fields have priority over extra fields.

        Args:
            events: List of events where each event is a dictionary with arbitrary keys and values.
            extra: Dictionary of extra keys and values to be added to each event.
        """
        for event in events:
            line = self.format_event({**extra, **event})
            data = line.encode("utf-8")
            self.sock.sendall(data)

    @staticmethod
    def format_event(event):
        """Represents a single event in key-value format suitable for indexing with Splunk. Keys are used verbatim
        without any modification. Values are first converted to string and then double quotes and newline characters
        are escaped with backslash.

        Args:
            event: Dictionary of keys and values.
        Returns:
            A string of key="value" pairs separated by spaces and terminated with \n.
        """
        kv = ""
        for key in event:
            val = str(event[key]).replace('"', '\\"').replace('\n', '\\n')
            kv += key + '="' + val + '" '
        return kv + "\n"


class SlackError(Exception):
    """Generic Slack API invocation error."""
    pass


class Slack:
    """Allows sending notifications to Splunk via Webhook.

    Attributes:
        url (str): Slack Webhook URL.
    Args:
        url (str): Slack Webhook URL.
    """

    def __init__(self, url):
        self.url = url

    def send_change_notification(self, added, removed):
        """Posts notification to Slack about added and removed users with special roles. No notification is posted
        when both `added` and `removed` lists are empty.

        Args:
            added: A list of added users where each entry is a dictionary with `id` and `role` keys.
            removed: A list of removed users where each entry is a dictionary with `id` and `role` keys.
        """

        def format_entry(entry):
            uid = entry["id"]
            role = entry["role"]
            display = entry.get("name") or entry["id"]
            return f"<https://vk.com/id{uid}|{display}> ({role})"

        markdown_lines = []
        if added:
            entries = [format_entry(entry) for entry in added]
            markdown_lines.append("*Added:* " + ", ".join(entries))
        if removed:
            entries = [format_entry(entry) for entry in removed]
            markdown_lines.append("*Removed:* " + ", ".join(entries))
        markdown = "\n".join(line for line in markdown_lines)
        self.send_notification(markdown)

    def send_notification(self, markdown):
        """Posts generic markdown to Slack channel. No notification is posted when `markdown` is empty.

        Args:
            markdown (str): Notification text with markdown formatting.
        """
        if not markdown:
            return
        payload = {"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": markdown}}]}
        r = requests.post(self.url, json=payload)
        r.raise_for_status()
        if not r.text == "ok":
            raise SlackError(r.text)


class State:
    """Allows persisting and restoring a list of users and roles.

    Args:
        path (str): Path to file used to persist state.
    """

    def __init__(self, path):
        self.path = path

    @staticmethod
    def decode_entries(blobs):
        """Decodes opaque strings (blobs) into entries.

        Args:
            blobs (iterable): Opaque strings.
        Returns:
            A list where each entry is a dictionary with `id` and `role` keys.
        """
        split_blobs = [blob.split(":", 2) for blob in blobs]
        return [{"id": uid, "role": role} for [uid, role] in split_blobs]

    @staticmethod
    def encode_entries(entries):
        """Encodes entries into opaque strings (blobs).

        Args:
            entries (iterable): A list where each entry is a dictionary with `id` and `role` keys.
        Returns:
            A list of opaque strings.
        """
        return [f"{entry['id']}:{entry['role']}" for entry in entries]

    def read_blobs(self):
        """Reads a list of opaque strings (blobs) from disk.

        Returns:
            A list of opaque strings suitable for comparison.
        """
        try:
            with open(self.path, "rt") as f:
                return [blob.strip() for blob in f.read().splitlines()]
        except FileNotFoundError:
            return []

    def write_blobs(self, blobs):
        """Writes a list of opaque strings (blobs) to disk.

        Args:
            blobs (iterable): A list of opaque strings.
        """
        with open(self.path, "wt") as f:
            f.writelines("\n".join(blobs))


def enrich_with_user_details(entry, users):
    """Enriches data with user details.

    Args:
        entry: Dictionary with a single required field `id` that contains user ID.
        users: Dictionary with user details keyed by user ID.
    Returns:
        The same entry with added user details.
    """
    user = users.get(entry["id"]) or {"name": ""}
    return {**user, **entry}


def main():
    timestamp = time.time()
    state_file = "/var/lib/vkgrpmon/state"
    vk_admin_roles = ["administrator", "creator"]

    vk_access_token = os.environ["VK_ACCESS_TOKEN"]
    vk_group_id = os.environ["VK_GROUP_ID"]
    slack_webhook_url = os.environ["SLACK_WEBHOOK_URL"]
    splunk_address = os.environ["SPLUNK_ADDRESS"]

    state = State(state_file)
    vk = Vk(vk_access_token)
    slack = Slack(slack_webhook_url)
    splunk = Splunk(splunk_address)

    group_managers = vk.get_group_managers(vk_group_id)
    group_admins = [entry for entry in group_managers if entry["role"] in vk_admin_roles]
    current_blobs = set(state.encode_entries(group_admins))
    previous_blobs = set(state.read_blobs())

    added_blobs = current_blobs - previous_blobs
    added_entries = state.decode_entries(added_blobs)
    removed_blobs = previous_blobs - current_blobs
    removed_entries = state.decode_entries(removed_blobs)

    changed_entries = [*removed_entries, *added_entries]
    changed_user_ids = [entry["id"] for entry in changed_entries]
    changed_users = vk.get_users(changed_user_ids)

    enriched_added_entries = [enrich_with_user_details(entry, changed_users) for entry in added_entries]
    enriched_removed_entries = [enrich_with_user_details(entry, changed_users) for entry in removed_entries]

    slack.send_change_notification(enriched_added_entries, enriched_removed_entries)
    splunk.write_events_batch(enriched_added_entries, timestamp=timestamp, change="added")
    splunk.write_events_batch(enriched_removed_entries, timestamp=timestamp, change="removed")

    state.write_blobs(current_blobs)


if __name__ == "__main__":
    main()
