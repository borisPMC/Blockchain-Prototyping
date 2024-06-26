"""Testing src.blockchain module."""
import sys
sys.path.append(r'J:\COMProfile\Documents\GitHub\E-payment2')

import hashlib
import json
from src.blockchain import Block, Blockchain


blockchain = Blockchain()

def test_block_creation():
    """Test creation of a block in the chain"""
    blockchain.create_block()

    latest_block = blockchain.last_block

    # The genesis block is created at initialization, so the length should be 2
    assert len(blockchain.chain) == 2
    assert latest_block['index'] == 1
    assert latest_block['timestamp'] is not None
    assert latest_block['proof'] is not None
    assert latest_block['previous_hash'] is not None

def test_create_transaction():
    """Test creation of a new transaction"""
    blockchain.new_transaction(sender='a', recipient='b', amount=1)

    transaction = blockchain.transactions[-1]

    assert transaction
    assert transaction['sender'] == 'a'
    assert transaction['recipient'] == 'b'
    assert transaction['amount'] == 1

def test_block_resets_transactions():
    """Test transations reset"""
    initial_length = len(blockchain.transactions)
    blockchain.create_block()
    current_length = len(blockchain.transactions)

    assert initial_length == 1
    assert current_length == 0

def test_return_last_block():
    """Test last_block() method"""
    created_block = blockchain.last_block

    assert len(blockchain.chain) == 3
    assert created_block is blockchain.chain[-1]

def test_hash_is_correct():
    """Test hash method returns the correst hash"""
    new_block = blockchain.last_block
    new_block_json = json.dumps(blockchain.last_block, sort_keys=True).encode()
    new_hash = hashlib.sha256(new_block_json).hexdigest()

    assert len(new_hash) == 64
    assert new_hash == blockchain.hash(new_block)

def test_valid_nodes():
    """Test valid registered nodes."""
    blockchain.register_node('http://192.168.0.1:5000')
    assert '192.168.0.1:5000' in blockchain.nodes

def test_idempotency():
    """Test nodes duplication"""
    blockchain.register_node('http://192.168.0.1:5000')
    blockchain.register_node('http://192.168.0.1:5000')

    assert len(blockchain.nodes) == 1

def test_malformed_nodes():
    """Test malformed nodes"""
    blockchain = Blockchain()

    blockchain.register_node('http//192.168.0.1:5000')
    assert '192.168.0.1:5000' not in blockchain.nodes
