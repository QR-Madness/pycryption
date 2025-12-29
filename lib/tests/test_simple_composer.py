from lib.SimpleEncryptionComposer import SimpleEncryptionComposer
import unittest


class TestSimpleComposer(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.composer = SimpleEncryptionComposer()

    def test_composer_initialization(self):
        """Test that SimpleComposer initializes without errors."""
        self.assertIsNotNone(self.composer)

    def test_composer_instance(self):
        """Test that SimpleComposer creates a valid instance."""
        self.assertIsInstance(self.composer, SimpleEncryptionComposer)


if __name__ == "__main__":
    unittest.main()
