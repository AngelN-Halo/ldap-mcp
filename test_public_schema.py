"""Offline regression checks for the illustrative public LDAP schema."""
import unittest
from unittest.mock import patch

import server


class PublicSchemaTest(unittest.TestCase):
    def test_custom_attribute_allowlist_is_illustrative(self):
        self.assertIn("isdSiteCode", server.ISD_QUERYABLE_USER_ATTRIBUTES)
        self.assertIn("isdJobCategory", server.ISD_QUERYABLE_USER_ATTRIBUTES)
        self.assertIn("DirXML-ADContext", server.ISD_QUERYABLE_USER_ATTRIBUTES)
        self.assertIn("nrfMemberOf", server.ISD_MEMBERSHIP_ATTRIBUTES)

    def test_custom_filter_uses_fictional_names_and_escapes_values(self):
        filt = server._isd_user_filter(
            query="A*(B)", site_code="SITE-A", job_category="CATEGORY-1"
        )
        self.assertIn("(isdSiteCode=SITE-A)", filt)
        self.assertIn("(isdJobCategory=CATEGORY-1)", filt)
        self.assertIn(r"isdPreferredSurname=*A\2a\28B\29*", filt)

    def test_csv_row_uses_fictional_fields_and_generic_columns(self):
        row = server._csv_row_for_isd_user({
            "cn": "Example Person", "mail": "person@example.org",
            "isdWorkforceId": "PERSON-1", "isdSiteCode": "SITE-A",
            "isdPreviousSiteCode": "SITE-B", "isdJobCategory": "CATEGORY-1",
        })
        self.assertEqual(row["SiteCode"], "SITE-A")
        self.assertEqual(row["PreviousSiteCode"], "SITE-B")
        self.assertEqual(row["JobCategory"], "CATEGORY-1")
        self.assertEqual(row["ExternalPersonId"], "PERSON-1")

    def test_identity_lookup_filter_uses_fictional_attribute(self):
        self.assertIn("(isdWorkforceId=PERSON-1)", server._identity_filter("PERSON-1"))


if __name__ == "__main__":
    unittest.main()
