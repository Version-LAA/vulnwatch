from django.test import TestCase
from django.contrib.auth import get_user_model
# Create your tests here.


class UsersManagersTests(TestCase):
    # test the creation of a user
    def test_create_user(self):
        User = get_user_model()
        user = User.objects.create_user(
            username="testuser",
            email="testuser@example.com",
            password="testpass1234",
        )
        self.assertEqual(user.username, "testuser")
        self.assertEqual(user.email, "testuser@example.com")
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    # test the creation of a super user
    def test_super_user(self):
        User = get_user_model()
        user = User.objects.create_superuser(
            username="testsuperuser",
            email="testsuperuser@example.com",
            password="testsuperuserpass1234",
        )
        self.assertEqual(user.username, "testsuperuser")
        self.assertEqual(user.email, "testsuperuser@example.com")
        self.assertTrue(user.is_active)
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
