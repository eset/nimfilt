import unittest
import nimfilt

class TestNameParsing(unittest.TestCase):
    def test_simple_name(self):
        n = nimfilt.NimName("@add__system_u2308@8")
        self.assertTrue(n.is_std())
        self.assertEqual(n.fnname, "add")
        self.assertEqual(n.pkgname, "system")
        self.assertEqual(n.suffix, "u2308")
        self.assertIsNone(n.ida_suffix)
        self.assertEqual(n.num_args, "@8")

    def test_name_all_fields(self):
        n = nimfilt.NimName("@add__system_u2308_1.link.88@16")
        self.assertTrue(n.is_std())
        self.assertEqual(n.fnname, "add")
        self.assertEqual(n.pkgname, "system")
        self.assertEqual(n.suffix, "u2308")
        self.assertEqual(n.ida_suffix, "_1")
        self.assertEqual(n.num_args, "@16")

    def test_init_name(self):
        n = nimfilt.NimInitName("@atmlibatssystemdotnim_Init000@0")
        self.assertTrue(n.is_std)
        self.assertEqual(n.fnname, "Init000")
        self.assertEqual(n.pkgname, "lib/system")
        self.assertIsNone(n.suffix)
        self.assertIsNone(n.ida_suffix)
        self.assertEqual(n.num_args, "@0")

    def test_wrong_name(self):
        with self.assertRaises(ValueError):
            nimfilt.NimName("____w64_mingwthr_remove_key_dtor")
        with self.assertRaises(ValueError):
            nimfilt.NimName("@atmlibatssystemdotnim_Init000@0")

        with self.assertRaises(ValueError):
            nimfilt.NimInitName("____w64_mingwthr_remove_key_dtor")
        with self.assertRaises(ValueError):
            nimfilt.NimInitName("@add__system_u2308@8")

class TestDemangling(unittest.TestCase):
    def test_func_name(self):
        n = nimfilt.NimName("@eqdestroy___stdZ80rivateZntpath_u119@4")
        self.assertEqual(n.fnname, "=destroy")
        self.assertEqual(n.pkgname, "std/Private/ntpath")


if __name__ == "__main__":
    unittest.main()
