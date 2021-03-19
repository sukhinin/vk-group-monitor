#!/usr/bin/python3

import os
import socket
import time

import requests


class VkError(Exception):
    """Generic VK API invocation error."""
    pass


class VkGroupManager:
    """Data class representing VK user with group management permissions.

    Attributes:
        id (str): User id.
        role (str): Group management permissions level.
        display_name (str): Display name for a user.
    Args:
        id (str or int): User id.
        role (str): Group management permissions level.
        display_name (str, optional): Display name for a user.
    """

    def __init__(self, id, role, display_name="<unknown>"):
        if not id:
            raise ValueError("Missing required argument: id")
        if not role:
            raise ValueError("Missing required argument: role")
        self.id = str(id)
        self.role = role
        self.display_name = display_name

    @property
    def is_admin(self):
        """bool: True when the user is a group administrator, False otherwise."""
        return self.role in ["administrator", "creator"]

    def add_user_details(self, user):
        """Enriches data with user details.

        Args:
            user (:obj:`VkUser`): VK user details. May be None.
        """
        if not user:
            return
        self.display_name = user.display_name

    def serialize(self):
        """Serializes data to an opaque string that contains all information about VK group manager.
        At the same time, opaque strings can be a member of a set or can be easily persisted to disk.

        Returns:
            (str): Opaque string.
        """
        return f"{self.id}:{self.role}:{self.display_name}"

    @staticmethod
    def deserialize(s):
        """Deserializes opaque string representation to an object.

        Args:
            s (str): String produced by a previous call to serialize() method.
        Returns:
            (obj:`VkGroupManager`): VkGroupManager instance.
        """
        [uid, role, display_name] = s.split(":", 3)
        return VkGroupManager(uid, role, display_name)


class VkUser:
    """Data class representing generic VK user.

    Attributes:
        id (str): User id.
        first_name (str): User's first name.
        last_name (str): User's last name.
    Args:
        id (str or int): User id.
        first_name (str, optional): User's first name.
        last_name (str, optional): User's last name.
    """

    def __init__(self, id, first_name="", last_name=""):
        if not id:
            raise ValueError("Missing required argument: id")
        self.id = str(id)
        self.first_name = first_name
        self.last_name = last_name

    @property
    def display_name(self):
        """str: User's display name or <anonymous> when name is not available."""
        if self.first_name and self.last_name:
            return self.last_name + " " + self.first_name
        elif self.first_name or self.last_name:
            return self.last_name + self.first_name
        else:
            return "<anonymous>"


class Vk:
    """Implements a subset of VK API.

    Attributes:
        api_version (str): supported VK API version
        access_token (str): VK access token
    Args:
        access_token (str): VK access token
    """

    def __init__(self, access_token):
        if not access_token:
            raise ValueError("Missing required argument: access_token")
        self.api_version = "5.52"
        self.access_token = access_token

    def get_group_managers_oneshot(self, group_id, offset=0):
        """Returns a list of group managers starting from specified offset.

        When the result set is too large, only a portion of it is returned to the caller from
        a single method invocation. Subsequent invocations with increased offsets are necessary
        to retrieve the full results.

        Note:
            To get all results from a single call use get_group_managers() method.
        Args:
            group_id (str): Group identifier.
            offset (int, optional): Starting offset in members list. Defaults to 0.
        Returns:
            :obj:`list` of :obj:`VkGroupManager`: A list group managers.
        """
        group_managers = []
        data = self.call("groups.getMembers", filter="managers", group_id=group_id, offset=str(offset))
        for item in data["items"]:
            manager = VkGroupManager(item["id"], item["role"])
            group_managers.append(manager)
        return group_managers

    def get_group_managers(self, group_id):
        """Returns a list of group managers. When the result set is too large to be returned in a single
        API call, this method will make additional calls to retrieve the full results.

        Args:
            group_id (str): Group identifier.
        Returns:
            :obj:`list` of :obj:`VkGroupManager`: List of group managers.
        """
        managers = []
        while True:
            items = self.get_group_managers_oneshot(group_id, len(managers))
            if not items:
                break
            managers.extend(items)
        return managers

    def get_users_oneshot(self, user_ids):
        """Returns a list of user details. VK API is limited to returning no more than 1000 users in a single call.
        It's advised to call get_users() method that works around this limitation by performing multiple API calls.

        Args:
            user_ids (:obj:`list` of str): A list of user IDs. Should contain no more than 1000 elements.
        Returns:
            :obj:`list` of :obj:`VkUser`: List of VK user details.
        """
        users = []
        data = self.call("users.get", user_ids=",".join(user_ids))
        for item in data:
            user = VkUser(item["id"], item["first_name"], item["last_name"])
            users.append(user)
        return users

    def get_users(self, user_ids, chunk_size=1000):
        """Returns a list of user details. When the list of user IDs is too big, this method will split it into chunks
        and make multiple API calls to get the full results.

        Args:
            user_ids (:obj:`list` of str): A list of user IDs.
            chunk_size (int): A number of user IDs that can be requested in a single API call.
        Returns:
            :obj:`list` of :obj:`VkUser`: List of VK user details.
        """
        users = []
        for i in range(0, len(user_ids), chunk_size):
            ids_chunk = user_ids[i:i + chunk_size]
            users_chunk = self.get_users_oneshot(ids_chunk)
            users.extend(users_chunk)
        return users

    def call(self, method, **kwargs):
        """ Calls the specified VK API method. Method name and arguments are used 'as is' without
        any processing or encoding.

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
            events (:obj:`list` of :obj:`dict`): List of events where each event is an arbitrary dictionary.
            extra (:obj:`dict`): Dictionary of extra fields to be included in every event.
        """
        for event in events:
            self.write_event(event, **extra)

    def write_event(self, event, **extra):
        """Writes a single event to Splunk.

        Note:
            Event fields have priority over extra fields.

        Args:
            event (:obj:`dict`): Arbitrary dictionary.
            extra (:obj:`dict`): Dictionary of extra fields to be included in event.
        """
        line = self.format_event({**extra, **event})
        data = line.encode("utf-8")
        self.sock.sendall(data)

    @staticmethod
    def format_event(event):
        """Formats an event in key-value format suitable for indexing with Splunk. Keys are used verbatim
        without any modification. Values are first converted to string and then double quotes and newline
        characters are escaped with backslash.

        Args:
            event (:obj:`dict`): Dictionary of arbitrary keys and values.
        Returns:
            A string of key="value" pairs separated by spaces and terminated with \n.
        """
        kv = ""
        for key in event:
            val = str(event[key]).replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
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
        if not url:
            raise ValueError("Missing required argument: url")
        self.url = url

    def send_change_notification(self, added, removed, prefix=""):
        """Posts notification to Slack about added and removed users with special roles. No notification
        is posted when both `added` and `removed` lists are empty.

        Args:
            added (:obj:`list` of `VkGroupManager`): A list of added group managers.
            removed (:obj:`list` of :obj:`VkGroupManager`): A list of removed group managers.
            prefix (str): Arbitrary markdown that will be included in notification.
        """

        def format_group_manager(manager):
            return f"<https://vk.com/id{manager.id}|{manager.display_name}> ({manager.role})"

        markdown_lines = []
        if added:
            entries = [format_group_manager(entry) for entry in added]
            markdown_lines.append("*Added:* " + ", ".join(entries))
        if removed:
            entries = [format_group_manager(entry) for entry in removed]
            markdown_lines.append("*Removed:* " + ", ".join(entries))
        markdown = "\n".join(line for line in markdown_lines)
        if prefix:
            markdown = prefix + "\n" + markdown
        self.send_markdown(markdown)

    def send_markdown(self, markdown):
        """Posts generic markdown to Slack channel. No notification is posted when `markdown` is empty.

        Args:
            markdown (str): Text with markdown formatting.
        """
        if not markdown:
            return
        payload = {"blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": markdown}}]}
        r = requests.post(self.url, json=payload)
        r.raise_for_status()
        if not r.text == "ok":
            raise SlackError(r.text)


class State:
    """Allows persisting a list of opaque strings to disk.

    Args:
        path (str): Path to file used to store state.
    """

    def __init__(self, path):
        if not path:
            raise ValueError("Missing required argument: path")
        self.path = path

    def read(self):
        """Reads a list of opaque strings from disk.

        Returns:
            (:obj:`list` of str): List of opaque strings or an empty list when no persisted state found.
        """
        try:
            with open(self.path, "rt") as f:
                return [line.strip() for line in f.read().splitlines()]
        except FileNotFoundError:
            return []

    def write(self, lines):
        """Writes a list of opaque strings to disk.

        Args:
            lines (iterable): List of opaque strings.
        """
        with open(self.path, "wt") as f:
            f.writelines("\n".join(lines))


def main():
    timestamp = time.time()

    # Read configuration parameters from environment variables.
    state_file = os.environ["STATE_FILE"]
    vk_access_token = os.environ["VK_ACCESS_TOKEN"]
    vk_group_id = os.environ["VK_GROUP_ID"]
    slack_webhook_url = os.environ["SLACK_WEBHOOK_URL"]
    splunk_address = os.environ["SPLUNK_ADDRESS"]

    state = State(state_file)
    vk = Vk(vk_access_token)
    slack = Slack(slack_webhook_url)
    splunk = Splunk(splunk_address)

    # Get current and previous group admins. Entries are represented as opaque strings suitable for set operations.
    # At this point there are no user details in VkGroupManager objects, so serialized data will not contain
    # user display names.
    group_managers = vk.get_group_managers(vk_group_id)
    group_admins = [gm for gm in group_managers if gm.is_admin]
    current_group_admin_strings = set([ga.serialize() for ga in group_admins])
    previous_group_admin_strings = set(state.read())

    # Determine sets of users that have been added or removed from group admins.
    removed_group_admin_strings = previous_group_admin_strings - current_group_admin_strings
    added_group_admin_strings = current_group_admin_strings - previous_group_admin_strings

    # Deserialize entries from opaque strings.
    removed_group_admins = [VkGroupManager.deserialize(s) for s in removed_group_admin_strings]
    added_group_admins = [VkGroupManager.deserialize(s) for s in added_group_admin_strings]

    # Enrich entries of newly added VK group admins with user details.
    changed_group_admins = removed_group_admins + added_group_admins
    user_ids = [ga.id for ga in changed_group_admins]
    users = {user.id: user for user in vk.get_users(user_ids)}
    for ga in changed_group_admins:
        ga.add_user_details(users.get(ga.id))

    # Send notifications to Slack and Splunk.
    slack.send_change_notification(added_group_admins, removed_group_admins,
                                   prefix="Изменения в группе " + vk_group_id)
    splunk.write_events_batch([vars(ga) for ga in added_group_admins],
                              timestamp=timestamp, op="add", group_id=vk_group_id)
    splunk.write_events_batch([vars(ga) for ga in removed_group_admins],
                              timestamp=timestamp, op="remove", group_id=vk_group_id)

    # Persist current VK group admins to disk. These objects are already serialized, so there's no need
    # to serialize then again.
    state.write(current_group_admin_strings)

    # Write event to Splunk on successful execution. Absence of events with op="check" can be used
    # to detect problems with monitoring pipeline.
    splunk.write_event({}, timestamp=timestamp, op="check", group_id=vk_group_id)


if __name__ == "__main__":
    main()
