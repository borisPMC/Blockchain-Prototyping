import unittest
import sys
sys.path.append(r"J:\COMProfile\Documents\GitHub\E-payment2")

from Crypto.PublicKey import RSA
from src.blockchain import Blockchain

class TestBlockchain(unittest.TestCase):

    # Wallet Address: F3EAJcquzRbKUxgKH1hfsVYJ6VdHe4JfDx4ZhLNhH9JZ



    def setUp(self):
        self.blockchain = Blockchain()
        self.private_key, self.public_key = self.generate_keys()

    def generate_keys(self):
        key = RSA.generate(2048)
        private_key = key.export_key().decode()
        public_key = key.publickey().export_key().decode()
        return private_key, public_key

    def test_new_transaction(self):
        initial_transaction_count = len(self.blockchain.transactions)
        sample_transaction = {
            "sender": "F3EAJcquzRbKUxgKH1hfsVYJ6VdHe4JfDx4ZhLNhH9JZ",
            "recipient": "recipient",
            "amount": 10
        }

        self.blockchain.new_transaction(sample_transaction, SK=self.private_key, PK=self.public_key)
        self.assertEqual(len(self.blockchain.transactions), initial_transaction_count + 1)

    def test_last_block(self):
        last_block = self.blockchain.last_block
        self.assertEqual(last_block, self.blockchain.chain[-1])

    # Add more test methods as needed...

if __name__ == '__main__':
    unittest.main()