import unittest
from unittest import mock

from vkgrpmon import VkGroupManager, VkUser, Vk, Splunk, Slack, State


class VkGroupManagerTestCase(unittest.TestCase):
    def test_init_should_validate_args(self):
        with self.assertRaises(ValueError):
            VkGroupManager("", "role")
        with self.assertRaises(ValueError):
            VkGroupManager("id", "")

    def test_is_admin_should_check_if_manager_is_in_admin_role(self):
        self.assertTrue(VkGroupManager("id", "creator").is_admin)
        self.assertTrue(VkGroupManager("id", "administrator").is_admin)
        self.assertFalse(VkGroupManager("id", "moderator").is_admin)

    def test_add_user_details_should_add_user_details(self):
        manager = VkGroupManager("id", "role")
        user = VkUser("id", "First", "Last")
        manager.add_user_details(user)
        self.assertEqual(manager.display_name, user.display_name)

    def test_deserialize_should_restore_serialized_objects(self):
        manager = VkGroupManager("id", "role", "display name")
        serialized = manager.serialize()
        deserialized = VkGroupManager.deserialize(serialized)
        self.assertEqual(vars(manager), vars(deserialized))


class VkUserTestCase(unittest.TestCase):
    def test_init_should_validate_args(self):
        with self.assertRaises(ValueError):
            VkUser("")

    def test_display_name_should_return_display_name(self):
        self.assertEqual(VkUser("id").display_name, "<anonymous>")
        self.assertEqual(VkUser("id", first_name="First").display_name, "First")
        self.assertEqual(VkUser("id", last_name="Last").display_name, "Last")
        self.assertEqual(VkUser("id", first_name="First", last_name="Last").display_name, "Last First")


class VkTestCase(unittest.TestCase):
    def test_init_should_validate_args(self):
        with self.assertRaises(ValueError):
            Vk("")

    @mock.patch.object(Vk, "call")
    def test_get_group_managers_oneshot_should_call_api(self, mocked):
        mocked.return_value = {"items": []}
        Vk("token").get_group_managers_oneshot("gid", offset=10)
        mocked.assert_called_with("groups.getMembers", filter="managers", group_id="gid", offset=str(10))

    @mock.patch.object(Vk, "call")
    def test_get_group_managers_oneshot_should_return_managers(self, mocked):
        mocked.return_value = {"items": [{"id": "id1", "role": "role1"}, {"id": "id2", "role": "role2"}]}
        managers = Vk("token").get_group_managers_oneshot("gid")
        expected = [VkGroupManager("id1", "role1"), VkGroupManager("id2", "role2")]
        self.assertEqual([vars(m) for m in managers], [vars(e) for e in expected])

    @mock.patch.object(Vk, "get_group_managers_oneshot")
    def test_get_group_managers_should_call_oneshot_method_with_pagination(self, mocked):
        mocked.side_effect = [[VkGroupManager("id", "role")], []]
        Vk("token").get_group_managers("gid")
        mocked.assert_has_calls([mock.call("gid", 0), mock.call("gid", 1)])

    @mock.patch.object(Vk, "get_group_managers_oneshot")
    def test_get_group_managers_should_return_managers(self, mocked):
        mocked.side_effect = [[VkGroupManager("id1", "role1"), VkGroupManager("id2", "role2")],
                              [VkGroupManager("id3", "role3")], []]
        managers = Vk("token").get_group_managers("gid")
        expected = [VkGroupManager("id1", "role1"), VkGroupManager("id2", "role2"), VkGroupManager("id3", "role3")]
        self.assertEqual([vars(m) for m in managers], [vars(e) for e in expected])

    @mock.patch.object(Vk, "call")
    def test_get_users_oneshot_should_call_api(self, mocked):
        mocked.return_value = []
        Vk("token").get_users_oneshot(["id1", "id2"])
        mocked.assert_called_with("users.get", user_ids="id1,id2")

    @mock.patch.object(Vk, "call")
    def test_get_users_oneshot_should_return_users(self, mocked):
        mocked.return_value = [{"id": "id1", "first_name": "first1", "last_name": "last1"},
                               {"id": "id2", "first_name": "first2", "last_name": "last2"}]
        users = Vk("token").get_users_oneshot("id1,id2")
        expected = [VkUser("id1", first_name="first1", last_name="last1"),
                    VkUser("id2", first_name="first2", last_name="last2")]
        self.assertEqual([vars(m) for m in users], [vars(e) for e in expected])

    @mock.patch.object(Vk, "get_users_oneshot")
    def test_get_users_should_call_oneshot_method_with_chunking(self, mocked):
        mocked.side_effect = [[], []]
        Vk("token").get_users(["id1", "id2", "id3", "id4", "id5"], chunk_size=3)
        mocked.assert_has_calls([mock.call(["id1", "id2", "id3"]), mock.call(["id4", "id5"])])

    @mock.patch.object(Vk, "get_users_oneshot")
    def test_get_users_should_return_users(self, mocked):
        mocked.side_effect = [[VkUser("id1", first_name="first1", last_name="last1")],
                              [VkUser("id2", first_name="first2", last_name="last2")]]
        users = Vk("token").get_users(["id1", "id2"], chunk_size=1)
        expected = [VkUser("id1", first_name="first1", last_name="last1"),
                    VkUser("id2", first_name="first2", last_name="last2")]
        self.assertEqual([vars(u) for u in users], [vars(e) for e in expected])


class SplunkTestCase(unittest.TestCase):
    @mock.patch.multiple("socket.socket", connect=mock.DEFAULT, shutdown=mock.DEFAULT)
    def test_init_should_connect_socket(self, **kwargs):
        mocked_connect = kwargs["connect"]
        Splunk("localhost:9999")
        mocked_connect.assert_called_once_with(("localhost", 9999))

    @mock.patch.multiple("socket.socket", connect=mock.DEFAULT, shutdown=mock.DEFAULT, sendall=mock.DEFAULT)
    def test_write_event_should_send_formatted_data_with_extra_fields(self, **kwargs):
        mocked_sendall = kwargs["sendall"]
        Splunk("localhost:9999").write_event({"event_key": "event_value"}, extra_key="extra_value")
        expected = Splunk.format_event({"extra_key": "extra_value", "event_key": "event_value"})
        mocked_sendall.assert_called_once_with(expected.encode("utf-8"))

    @mock.patch.multiple("socket.socket", connect=mock.DEFAULT, shutdown=mock.DEFAULT, sendall=mock.DEFAULT)
    def test_write_event_should_event_fields_over_extra_fields(self, **kwargs):
        mocked_sendall = kwargs["sendall"]
        Splunk("localhost:9999").write_event({"key": "event_value"}, key="extra_value")
        expected = Splunk.format_event({"key": "event_value"})
        mocked_sendall.assert_called_once_with(expected.encode("utf-8"))

    @mock.patch.object(Splunk, "write_event")
    @mock.patch.multiple("socket.socket", connect=mock.DEFAULT, shutdown=mock.DEFAULT)
    def test_write_events_batch_should_call_write_event_method_for_each_event(self, mocked_write_event, **kwargs):
        Splunk("localhost:9999").write_events_batch([{"key1": "value1"}, {"key2": "value2"}], extra_key="extra_value")
        mocked_write_event.assert_has_calls([mock.call({"key1": "value1"}, extra_key="extra_value"),
                                             mock.call({"key2": "value2"}, extra_key="extra_value")])

    def test_format_event_should_return_key_value_pairs(self):
        event = {"key1": "value1", "key2": "value2"}
        formatted = Splunk.format_event(event)
        self.assertEqual(formatted, 'key1="value1" key2="value2" \n')

    def test_format_event_should_return_escape_special_characters_in_values(self):
        event = {"key1": "\"a\"", "key2": "a\nb", "key3": "a\rb"}
        formatted = Splunk.format_event(event)
        self.assertEqual(formatted, 'key1="\\"a\\"" key2="a\\nb" key3="a\\rb" \n')


class SlackTestCase(unittest.TestCase):
    def test_init_should_validate_args(self):
        with self.assertRaises(ValueError):
            Slack("")

    @mock.patch.object(Slack, "send_markdown")
    def test_send_change_notification_should_call_send_markdown(self, mocked_send_markdown):
        added = [VkGroupManager("id1", "role1", "name1"), VkGroupManager("id2", "role2", "name2")]
        removed = [VkGroupManager("id3", "role3", "name3"), VkGroupManager("id4", "role4", "name4")]
        Slack("url").send_change_notification(added, removed)
        expected = "\n".join(["*Added:* <https://vk.com/idid1|name1> (role1), <https://vk.com/idid2|name2> (role2)",
                              "*Removed:* <https://vk.com/idid3|name3> (role3), <https://vk.com/idid4|name4> (role4)"])
        mocked_send_markdown.assert_called_once_with(expected)

    @mock.patch.object(Slack, "send_markdown")
    def test_send_change_notification_should_handle_empty_added_list(self, mocked_send_markdown):
        added = []
        removed = [VkGroupManager("id3", "role3", "name3"), VkGroupManager("id4", "role4", "name4")]
        Slack("url").send_change_notification(added, removed)
        expected = "*Removed:* <https://vk.com/idid3|name3> (role3), <https://vk.com/idid4|name4> (role4)"
        mocked_send_markdown.assert_called_once_with(expected)

    @mock.patch.object(Slack, "send_markdown")
    def test_send_change_notification_should_handle_empty_removed_list(self, mocked_send_markdown):
        added = [VkGroupManager("id1", "role1", "name1"), VkGroupManager("id2", "role2", "name2")]
        removed = []
        Slack("url").send_change_notification(added, removed)
        expected = "*Added:* <https://vk.com/idid1|name1> (role1), <https://vk.com/idid2|name2> (role2)"
        mocked_send_markdown.assert_called_once_with(expected)


class StateTestCase(unittest.TestCase):
    def test_init_should_validate_args(self):
        with self.assertRaises(ValueError):
            State("")

    @mock.patch("builtins.open", new_callable=mock.mock_open)
    def test_read_should_open_specified_file(self, mocked_open):
        State("file_path").read()
        mocked_open.assert_called_once_with("file_path", "rt")

    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data="line1\nline2\nline3")
    def test_read_should_return_lines(self, mocked_open):
        state = State("file_path").read()
        self.assertEqual(state, ["line1", "line2", "line3"])

    @mock.patch("builtins.open", new_callable=mock.mock_open, read_data="line1\nline2\nline3")
    def test_read_should_return_empty_list_when_file_not_found(self, mocked_open):
        mocked_open.side_effect = FileNotFoundError
        state = State("file_path").read()
        self.assertEqual(state, [])

    @mock.patch("builtins.open", new_callable=mock.mock_open)
    def test_write_should_open_specified_file(self, mocked_open):
        State("file_path").write([])
        mocked_open.assert_called_once_with("file_path", "wt")

    @mock.patch("builtins.open", new_callable=mock.mock_open)
    def test_read_should_write_lines_to_file(self, mocked_open):
        State("file_path").write(["line1", "line2", "line3"])
        mocked_open().writelines.assert_called_once_with("line1\nline2\nline3")


if __name__ == '__main__':
    unittest.main()
