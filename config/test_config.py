from config import NtfConfig


class TestConfig:
    def test_validate_tnsa_config(self):
        config = NtfConfig('examples/tnsa.yaml')

    def test_validate_nsa_config(self):
        config = NtfConfig('examples/nsa.yaml')

    def test_validate_sme_config(self):
        config = NtfConfig('examples/sme.yaml')
