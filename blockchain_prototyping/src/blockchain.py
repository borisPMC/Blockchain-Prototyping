"""Blockchain module"""
import json
import hashlib
from base58 import b58encode_check
import base64
from hashlib import sha256
from datetime import datetime

from uuid import uuid4
from urllib.parse import urlparse

from typing import Any, List, Set, Dict, TypedDict
from dataclasses import dataclass
import requests

from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

from flask import Flask, request, jsonify

app = Flask(__name__)

class Transaction:

    def __init__(self, sender: str, recipient: str, amount: float, sk: bytes) -> None:
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = self.setSign(sk)
    
    
    def getDict(self) -> dict:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "signature": self.signature
        }
    
    def getDict2(self) -> dict:
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "signature": base64.b64encode(self.signature).decode()  # Convert bytes to string
        }

    def __str__(self):
        return f"<Transaction sender={self.sender} recipient={self.recipient} amount={self.amount} signature={self.signature}>"

    def getSender(self):
        return self.sender
    
    def getRecipient(self):
        return self.recipient
    
    def getAmount(self):
        return self.amount

    def getHashed(self) -> str:
        return sha256((self.sender + self.recipient + str(self.amount)).encode()).hexdigest()
    
    def setSign(self, SK: bytes) -> bytes:
        signer = pkcs1_15.new(RSA.import_key(SK))
        msg_hash = SHA256.new(self.getHashed().encode())
        return signer.sign(msg_hash)
    
    def getMerkelHashed(self) -> int:
        return hash(json.dumps(self.getDict(), sort_keys=True))

    def verifySign(self, key: bytes) -> bool: # key can be private or public of the same set
        local_key = pkcs1_15.new(RSA.import_key(key))
        msg_hash = SHA256.new(self.getHashed().encode())
        try:
            local_key.verify(msg_hash, self.signature)
            return True
        except:
            print("Invalid Key!")
            return False
        
    def setCoinbase(self) -> None:
        self.signature = "coinbase"

class Block:

    def __init__(self, index: int, timestamp: str, transactions: List[Transaction], proof: int, previous_hash: str, current_hash: str, difficulty: int, nonce: int, merkle_root: str, data: str):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.proof = proof
        self.previous_hash = previous_hash
        self.current_hash = current_hash
        self.difficulty = difficulty
        self.nonce = nonce
        self.merkle_root = merkle_root
        self.data = data

    def getDict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.getDict() for tx in self.transactions],
            "proof": self.proof,
            "previous_hash": self.previous_hash,
            "current_hash": self.current_hash,
            "difficulty": self.difficulty,
            "nonce": self.nonce,
            "merkle_root": self.merkle_root,
        }
    
    def str(self):
        return f"<Block index={self.index} timestamp={self.timestamp} transactions={self.transactions} proof={self.proof} previous_hash={self.previous_hash} current_hash={self.current_hash} difficulty={self.difficulty} nonce={self.nonce} merkle_root={self.merkle_root} data={self.data}>"
    
    def hash(self) -> str:
        """Creates a SHA-256 hash of a Block.

        :param block: <Block>
        :return: <str> Hash
        """
        # The dictionary has to be Ordered, or we'll have inconsistent hashes.
        encoded_block = json.dumps(self.getDict(), sort_keys=True).encode()
        return sha256(encoded_block).hexdigest()

class Blockchain:
    """The main blockchain class."""
    TARGET_TIME = 10

    def __init__(self) -> None:
        self.transactions: List[Transaction] = []
        self.chain: List[Block] = []    # The chain container

        self.nodes: Set[str] = set()
        self.node_id: str = str(uuid4()).replace('-', '')

        # Create the genesis block
        print("Creating genesis block")
        self.create_block(proof=1, prev_hash="genesis")

    def create_block(self, proof: int=None, prev_hash: str=None):
        """Create a new Block in the Blockchain
        the Block should be immutable.

        :param proof: <int> The proof given by the Proof of Work algorithm
        :param previous_hash: <str> Hash of the previous Block
        :return: <Block> A new Block
        """
        block = Block(
                    index = len(self.chain),
                    timestamp = str(datetime.now()),
                    transactions = self.transactions,
                    proof = proof or self.proof_of_work(self.last_block),
                    previous_hash = prev_hash or (self.last_block).hash(),
                    current_hash = self.calculate_current_hash(proof,prev_hash),
                    difficulty = self.calculate_difficulty(),
                    nonce = self.calculate_nonce(proof, prev_hash),
                    merkle_root = self.calculate_merkle_root(self.transactions),
                    data = self.calculate_data()
                )

        # Reset the current transactions list
        self.transactions = []

        # Append block to the chain
        self.chain.append(block)
    
    def new_transaction(self, tx: Transaction, SK: bytes, PK: bytes) -> int:
        # Verify before appending Transaction
        if (tx.verifySign(SK) and tx.verifySign(PK)):
            self.transactions.append(tx)
            return (self.last_block).index + 1
        else:
            print("Add transaction failed")
            return (self.last_block).index
        

    @property
    def last_block(self) -> Block:
        """Get the last block in the chain.

        :return: <Block> The last Block in the chain.
        """
        return self.chain[-1]
    
    # Create a preliminary block with the content that is available
    def calculate_current_hash(self, proof: int, prev_hash: str) -> str:
        txList = [] # List of Dicts
        for tx in self.transactions:
            txList.append(tx.getDict())
        """Calculate the hash of the current block."""
        pre_block = {
            'index': len(self.chain),
            'timestamp': str(datetime.now()),
            'transactions': txList,
            'proof': proof,
            'previous_hash': prev_hash
        }

        # The dictionary has to be Ordered, or we'll have inconsistent hashes.
        encoded_block = json.dumps(pre_block, sort_keys=True).encode()
        return sha256(encoded_block).hexdigest()
           
    def calculate_data(self) -> List[Transaction]:
        """Calculate the data for the current block."""
        return self.transactions
        
    def calculate_difficulty(self) -> int:
        """Calculate the difficulty of the next block based on the time taken to generate the previous blocks.
        :return: <int> Difficulty
        """
        if len(self.chain) < 2:
            return 4  # Initial difficulty

        # Calculate the time taken to generate the last block
        last_block = self.chain[-1]
        second_last_block = self.chain[-2]
        time_taken = datetime.fromisoformat(last_block.timestamp) - datetime.fromisoformat(second_last_block.timestamp)

        # If the time taken is greater than the target time, decrease the difficulty
        if time_taken.total_seconds() > self.TARGET_TIME:
            return last_block.difficulty - 1
        # If the time taken is less than the target time, increase the difficulty
        elif time_taken.total_seconds() < self.TARGET_TIME:
            return last_block.difficulty + 1

        return last_block.difficulty

    def proof_of_work(self, last_block: Block) -> int:
        """Proof of Work Algorithm:
        - Find a number p' such that hash(pp') contains leading 4 zeroes, where p is the previous p'
        - p is the previous proof, and p' is the new proof
        :param last_block: <Block> The last Block
        :return: <int> Proof
        """
        last_proof = last_block.proof
        last_hash = last_block.hash()
        difficulty = self.calculate_difficulty()

        proof = 0
        while self.validate_proof(last_proof, proof, last_hash, difficulty) is False:
            proof += 1

        return proof

    @staticmethod
    def validate_proof(last_proof: int, proof: int, last_hash: str, difficulty: int) -> bool:
        """Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.
        """
        guess: bytes = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = sha256(guess).hexdigest()
        return guess_hash[:difficulty] == "0" * difficulty
    
    def calculate_nonce(self, last_proof: int, last_hash: str ) -> int:
        """Calculate the nonce for the current block."""

        difficulty = self.calculate_difficulty()
        nonce = 0
        while self.validate_proof(last_proof, nonce, last_hash, difficulty) is False:
            nonce += 1
        return nonce
    
    def calculate_merkle_root(self, txList: List[Transaction]) -> str:
        """Calculate the Merkle root of the transactions in the current block."""
        # Convert transactions to a list of hashes
        hashes = [tx.getMerkelHashed() for tx in txList]

        # If the list is empty, return a hash of an empty string
        if not hashes:
            return hash("")

        # While there is more than 1 hash in the list, keep hashing pairs of hashes
        while len(hashes) > 1:
            # If the number of hashes is odd, duplicate the last hash
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])

            # Hash pairs of hashes
            hashes = [hash(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]

        # The last remaining hash is the Merkle root
        return str(hashes[0])

    def validate_chain(self) -> bool:
        """Determine if a given blockchain is valid.

        :param chain: <List[Block]> A blockchain
        :return: <bool> True if valid, False if not
        """
        prev_block: Block = self.chain[0]
        current_index: int = 1

        while current_index < len(self.chain):

            block = self.chain[current_index]
            txList = block.transactions
            merkel = block.merkle_root # String

            # return False If the previous_hash of current block
            # is different from the previous block,
            if (self.calculate_merkle_root(txList) != merkel):
                return False

            print(f'{prev_block}')
            print(f'{block}')
            print("\n-----------\n")
            prev_block_hash = prev_block.hash()
            if block.previous_hash != prev_block_hash:
                return False

            # Check that the Proof of Work is correct
            difficulty = self.calculate_difficulty()
            if not self.validate_proof(prev_block.proof, block.proof, prev_block_hash, difficulty):
                return False

            prev_block = block
            current_index += 1

        # If everything is valid & gucci return True
        return True
    
    def get_balance(self, address: str) -> float:
        balance = 0.0
        for block in self.chain:
            for tx in block.transactions:
                if tx.getRecipient() == address:
                    balance += tx.getAmount()
                if tx.getSender() == address:
                    balance -= tx.getAmount()
        return balance

    def create_coinbase_transaction(self, recipient: str, amount: float, sk: bytes):

        coinbase_tx = Transaction("0", recipient, amount, sk)
        coinbase_tx.setCoinbase()
        self.transactions.append(coinbase_tx)
        self.create_block()
        return coinbase_tx

    def register_node(self, address: str) -> None:
        """Add a new node to the list of nodes.

        :param address: Address of node. Eg. 'http://127.0.0.1:5000'
        """
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like 'http://127.0.0.1:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def resolve_conflicts(self) -> bool:
        """The consensus algorithm, it resolves conflicts by
        replacing the chain with the longest one in the network.

        :return: <bool> True if the chain was replaced, False if not
        """
        neighbors = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbors:
            try:
                response = requests.get(f'http://{node}/chain')

                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']

                    # Check if the length is longer and the chain is valid
                    if length > max_length and self.validate_chain():
                        max_length = length
                        new_chain = chain
            except Exception as e:
                print(f"Error occurred while resolving conflicts: {e}")

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False
    
    @app.route('/create_coinbase_transaction', methods=['POST'])
    def create_coinbase_transaction1():
        data = request.get_json()
        recipient = data.get('recipient')
        amount = data.get('amount')

        if recipient is None or amount is None:
            return jsonify({'error': 'Missing recipient or amount'}), 400
    
        tx = blockchain.create_coinbase_transaction(recipient, amount, wallet.private_key)
        wallet.update_utxos(tx)
        return jsonify({'transaction': tx.getDict()}), 200

    # @app.route('/balance/<address>', methods=['GET'])
    # def get_balance1(address):
    #     balance = blockchain.get_balance(address)
    #     return jsonify({'balance': balance}), 200

class Wallet:
    def __init__(self):
        self.private_key, self.public_key = Wallet.generate_keys()
        self.address = self.public_key_to_address()
        self.utxos = []

    @staticmethod
    def generate_keys():
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    
    # P2PKH address
    def public_key_to_address(self, *args):
        # Hash the public key using SHA256
        hashed_public_key = hashlib.sha256((self.public_key)).hexdigest()

        address_bytes = bytes.fromhex(hashed_public_key)

        # Encode the address using Base58Check
        return b58encode_check(address_bytes).decode()

    def create_transaction(self, recipient: str, amount: float) -> Transaction:
        return Transaction(self.address, recipient, amount,self.private_key)
    
    def get_balance(self, *args):
        
        x = 0
        for utxo in self.utxos:
            x += utxo.getAmount()

        return x

    def update_utxos(self, tx: Transaction):
        amount_to_spend = self.get_balance()

        # Add received transaction to UTXO List
        if (tx.getRecipient() == self.address):
            self.utxos.append(tx)
        

        # Spend away transactions, assume sum(utxos.amount) >= tx.amount
        elif (tx.getSender() == self.address):
            new_utxos = (self.utxos).copy()
            needed_amount = tx.getAmount()
            for utxo in self.utxos:
                if needed_amount <= 0:
                    break
                else:
                    needed_amount -= utxo.getAmount()
                    new_utxos = new_utxos[1:]
            self.utxos = new_utxos

    
    def validate_block(self, block: Block) -> bool:
        # Recompute the hash of the block
        recomputed_hash = block.hash()

        # Check that the recomputed hash matches the given hash
        if recomputed_hash != block.current_hash:
            return False

        # Check that the previous_hash of the block matches the hash of the last block in the chain
        if len(blockchain.chain) > 0 and block.previous_hash != (blockchain.chain[-1]).hash():
            return False

        # Check that the proof of work is correct
        if not blockchain.validate_proof((blockchain.chain[-1]).proof, block.proof, (blockchain.chain[-1]).current_hash, block.difficulty):
            return False

        return True
    
    @app.route('/blocks', methods=['POST'])
    def receive_block():
        block = request.get_json()
        if blockchain.validate_block(block):
            blockchain.chain.append(block)
            return "Block added to the chain", 200
        else:
            return "Invalid block", 400

    @app.route('/blocks', methods=['GET'])
    def send_blocks():
        output = []
        for block in blockchain.chain:
            output.append(block.getDict())
        print(output)
        return json.dumps(output)
    
    @app.route('/balance', methods=['GET'])
    def get_wallet_balance():
        balance = wallet.get_balance()
        return jsonify({'balance': balance}), 200
    
    @app.route('/wallet/address', methods=['GET'])
    def get_wallet_address():
        address = wallet.public_key_to_address(wallet.public_key)
        return jsonify({'address': address}), 200
    
    @app.route('/create_transaction', methods=['POST'])
    def create_and_add_transaction():

        data = request.get_json()
        recipient = data.get('recipient')
        amount = data.get('amount')

        if recipient is None or amount is None:
            return jsonify({'error': 'Missing recipient or amount'}), 400
        
        utxos_sum = 0.0
        for tx in wallet.utxos:
            utxos_sum += tx.getAmount()

        if (amount > utxos_sum):
            return jsonify({'error': 'Not enough balance'}), 400
        
        new_tx = wallet.create_transaction(recipient, amount)
        wallet.update_utxos(new_tx)
        blockchain.new_transaction(new_tx, wallet.private_key, wallet.public_key)
        print(new_tx.getDict())
        return jsonify({'transaction': new_tx.getDict2()}), 200
    
if __name__ == '__main__':
    blockchain = Blockchain()
    wallet = Wallet()
    app.run(port=5000)