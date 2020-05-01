import sys
import json
from datetime import datetime
from utils_s3 import save_details, save_loglist, get_Date, safe_to_fetchlist, load_from_fetchlist
from hexbytes import HexBytes
from web3 import Web3
from eth_account import Account, messages

web3 = "None"
loglist = []

# Initialize Web3
infurl = "https://mainnet.infura.io/v3/23fd055821324e1cb652ae0c1955ae9e"
infurltest = "https://ropsten.infura.io/v3/c81785f09a5c4bde9727c8979e0aad70"
web3 = Web3(Web3.HTTPProvider(infurltest))

# Contract Details
contabi = '[{"constant": false, "inputs": [{"name": "_sig", "type": "string"}], "name": "addsig", "outputs": [], "payable": false, "stateMutability": "nonpayable", "type": "function"}, {"anonymous": false, "inputs": [{"indexed": false, "name": "signer", "type": "address"}, {"indexed": false, "name": "signature", "type": "string"}, {"indexed": false, "name": "chaindata", "type": "bytes32"}], "name": "Sign", "type": "event"}, {"constant": false, "inputs": [{"name": "_amount", "type": "uint256"}], "name": "transferfunds", "outputs": [], "payable": false, "stateMutability": "nonpayable", "type": "function"}, {"payable": true, "stateMutability": "payable", "type": "fallback"}, {"inputs": [], "payable": false, "stateMutability": "nonpayable", "type": "constructor"}, {"constant": true, "inputs": [], "name": "contractBalance", "outputs": [{"name": "", "type": "uint256"}], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": true, "inputs": [{"name": "", "type": "bytes32"}], "name": "db", "outputs": [{"name": "", "type": "address"}], "payable": false, "stateMutability": "view", "type": "function"}, {"constant": true, "inputs": [{"name": "_sig", "type": "string"}], "name": "getsig", "outputs": [{"name": "", "type": "address"}], "payable": false, "stateMutability": "view", "type": "function"}]'
contaddr = web3.toChecksumAddress("0x32e63Ce6184bF5C2a9EC295C52739F08179eC824")

# Helper Class
class HexJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, HexBytes):
            return obj.hex()
        return super().default(obj)

# Entry Object where an entry is equal to details of a transaction
# While the transaction is not mined yet, self.tx remains None
class Entry:
    def __init__(self, username, txhash, address, sig ):
        self.username = username
        self.txhash = txhash
        self.address = address
        #self.privkey = privkey
        self.sig = sig
        self.time = datetime.timestamp(datetime.now())
        self.tx = None


def create_chain_data(binFile = None, pk = None, username="Anonymous", test=True):
    global loglist
    # Check if file was uploaded else return "nofile"
    if binFile == b'':
        return "nofile", [], None, []
    # Create web3 account out of provided private key
    acct = create_acct(pk)
    # Hash provided file
    hashedFile = hash_file(binFile)
    # Sign hashed file
    sig = sign_file(acct, hashedFile)
    # Establish Connection to the contract and send tx
    txHash = callcontract(acct, sig, test)
    # Check for replay transactions and insufficient funds
    if txHash == "replaytx" :
        return "replaytx", [], None, []
    if txHash == "insufficient" :
        return "insufficient", [], None, []
    # Create Entry object, needed for storing every txs
    entry = Entry(username, txHash, acct.address, sig)
    _entry = {entry.address: {"username": entry.username, "txHash": entry.txhash, "address": entry.address,
                                  "sig": entry.sig, "time": entry.time, "tx": entry.tx}}
    # Fetchlist is a list of transactions that are not yet confirmed
    safe_to_fetchlist(_entry)
    # Loglist is used to provide JS pop up modals
    loglist.append(loglist + [get_Date(), f"Signer: {acct.address}", f"Signed File: {sig}", f"Tx Hash: {txHash}"])
    # Save to AWS Bucket
    save_details(newEntry=(sig, acct.address, acct.privateKey.hex(), txHash, username))
    save_loglist(loglist=loglist[0])
    loglist = []
    # Let the software check if maybe transactions in the fetchlist are now mined
    mine()
    return username, sig, acct.address, txHash

# Initialize connection to the contract through web3
def callcontract(acct, _data = None, test=True):
    global contabi, contaddr
    contaddr, web3, net = get_net_url(test)
    _from = acct.address
    _nonce = web3.eth.getTransactionCount(acct.address)
    _addr, _abi = load_dependencies(contaddr, contabi)
    _contract = web3.eth.contract(address=_addr, abi=_abi)
    _tx_calc = build_tx(_contract, _from, _nonce, _data)
    _gas = estimate_tx_gas(_tx_calc)
    _tx = build_tx(_contract, _from, _nonce, _data, _gas, web3.toWei('20', 'gwei'))
    _raw_tx = sign_tx(acct, _tx)
    _tx_hash = send_tx(_raw_tx)
    return _tx_hash


# Verify the provided signature and file
def verify_chain_data(binFile = None, sig = None, test=True):
    contaddr, web3, net = get_net_url(test=test)
    # Check if signature is valid
    if len(sig) != 132:
        print("NO VALID SIGNATURE")
        return 0, None, "signature"
    # If a file is provided, then the user triggered the action under the "Verify" tab, else "Who singed...?" tab
    if binFile:
        _hashedFile = hash_file(binFile)
        message = messages.encode_defunct(primitive=_hashedFile)
        _addr, _abi = load_dependencies(contaddr, contabi)
        _contract = web3.eth.contract(address=_addr, abi=_abi)
        _addr = _contract.functions.getsig(sig).call()
        addr = web3.eth.account.recover_message(message, signature=HexBytes(sig))
        # Verification if the address is either stored in the Smart Conract
        # and the signature and file result in the same address
        if _addr == addr:
            status = 1
        else:
            status = 2
        return status, _addr, addr

    # Calling the Smart Contract for verification
    if binFile == None and sig:
        _addr, _abi = load_dependencies(contaddr, contabi)
        _contract = web3.eth.contract(address=_addr, abi=_abi)
        _addr = _contract.functions.getsig(sig).call()
        if _addr and _addr != "0x0000000000000000000000000000000000000000":
            status2 = 1
        else:
            status2 = 2
        match = match_data(sig)
        return status2, _addr, match


#------------ Helper functions ------------------

# Checks if there are transactions in the fetchlist that are already mined but still
# no information about the tx (block info) attached
def mine():
    entryDict = load_from_fetchlist(history=False)
    max_mine = 2
    ed = {}
    for i in entryDict:
        if entryDict[i]["tx"] == None and max_mine >= 0 and datetime.timestamp(datetime.now())-entryDict[i]["time"] > 10:
            try:
                try:
                    tx = web3.eth.getTransaction(entryDict[i]["txHash"])
                except:
                    web3 = Web3(Web3.HTTPProvider(infurl))
                    tx = web3.eth.getTransaction(entryDict[i]["txHash"])
            except:
                web3 = Web3(Web3.HTTPProvider(infurltest))
                tx = web3.eth.getTransaction(entryDict[i]["txHash"])

            if tx.blockHash != None:
                entryDict[i]["tx"] = json.loads(json.dumps(dict(tx), cls = HexJsonEncoder))
                eD = i
                max_mine -= 1
                if max_mine != 2:
                    safe_to_fetchlist({eD:entryDict[i]})


def sign_file(_acct, _hashedFile):
    return web3.eth.account.sign_message(messages.encode_defunct(primitive=_hashedFile), private_key=_acct.privateKey).signature.hex()


def hash_file(_file):
    return web3.solidityKeccak( ["bytes"], [_file])


def genkey(rand = "random"):
    kp=None
    maxLoop = 0
    while kp == None and maxLoop <= 10:
        _rand = ''.join(format(ord(x), 'b') for x in rand)
        kp = web3.eth.account.create(_rand)
        maxLoop += 1
    loglist.append(loglist + [get_Date(), f"Address generated: {kp.address}", f"PrivKey: {kp.key.hex()}", f"Loopcount: {maxLoop}"])

    return kp.address, kp.key.hex()


def create_acct(_pk="f56a1e666b0e3db8c973a1343f3ddad7e05b3cbefbe745dd9c208c385548558b"):
    return web3.eth.account.privateKeyToAccount(_pk)


def load_dependencies(contaddr, contabi):
    addr = web3.toChecksumAddress(contaddr)
    abi = json.loads(contabi)
    return addr, abi


def send_tx(tx):
    try:
        return web3.eth.sendRawTransaction(tx.rawTransaction).hex()
    except ValueError as ex:
        print(ex)
        print(ex.args[0]["message"])
        print("..............................")
        if "insufficient" in ex.args[0]["message"]:
            return "insufficient"
        return "replaytx"


def sign_tx(acct, tx):
    return acct.signTransaction(tx)


def build_tx(contract, _from, nonce, data = None, gas = 10000, gasPrice = web3.eth.gasPrice):
    return contract.functions.addsig(data).buildTransaction({
        'from': _from,
        'nonce': nonce,
        'gas': gas,
        'gasPrice': gasPrice})


def estimate_tx_gas(tx):
    return web3.eth.estimateGas(tx)


def match_data(sig):
    data = load_from_fetchlist(history=False)
    print(data)
    for i in data:

        if sig == data[i]["sig"]:
            matchedData = data[i]
            return matchedData
    return False


def get_net_url(test):
    global web3, infurl, infurltest, contaddr
    if test == False:
        web3 = Web3(Web3.HTTPProvider(infurl))
        contaddr = web3.toChecksumAddress("0xc4053b2433c17651Dde609B6f4A57a700A18A185")
        return contaddr, web3, "USING MAINNET"
    else:
        web3 = Web3(Web3.HTTPProvider(infurltest))
        contaddr = web3.toChecksumAddress("0x32e63Ce6184bF5C2a9EC295C52739F08179eC824")
        return contaddr, web3, "USING TESTNET"


def history_slice(history, slices):
    count = 0
    nd = {}
    entries = len(list(history.items()))
    if slices > entries:
        slices = entries
    for a, b in history.items():
        if count >= entries - slices:
            nd = {**{a: b}, **nd}
        count += 1
    return nd