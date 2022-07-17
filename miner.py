import time, json, sha3, sys, os, requests, cpuinfo, pypresence, groestlcoin_hash, skein
from eth_account.messages import encode_defunct
from web3.auto import w3
from rich import print


MainNET = "http://so-travelling.at.playit.gg:51922"
# JunaidNET = 'https://node-2.siricoin.tech:5006' Junaid bad!!

configFile = "config.json"
TimeOUT = 1
RpcEnabled = True
hashes_per_list = 3000
hashrate_refreshRate = 10 # s


def hash():
    pass

def rgbPrint(string, color, end="\n"):
    print("[" + color + "]" + str(string) + "[/" + color + "]", end=end)

def Get_address():
    global address_valid, minerAddr

    if os.path.exists(configFile):
        address_valid = True
        with open(configFile) as f:
            data = json.load(f)
        minerAddr = data["address"]

    while not address_valid:
            minerAddr = input("Enter your SiriCoin address: ")
            try:
                address_valid = w3.isAddress(minerAddr)
            except:
                rgbPrint("The address you inputed is invalid, please try again", "red")
            if not address_valid:
                rgbPrint("The address you inputed is invalid, please try again", "red")
            else:
                with open(configFile, 'w') as outfile:
                    json.dump({"address": minerAddr}, outfile)
    

class SignatureManager(object):
    def __init__(self):
        self.verified = 0
        self.signed = 0
    
    def signTransaction(self, private_key, transaction):
        message = encode_defunct(text=transaction["data"])
        transaction["hash"] = w3.soliditySha3(["string"], [transaction["data"]]).hex()
        _signature = w3.eth.account.sign_message(message, private_key=private_key).signature.hex()
        signer = w3.eth.account.recover_message(message, signature=_signature)
        sender = w3.toChecksumAddress(json.loads(transaction["data"])["from"])
        if (signer == sender):
            transaction["sig"] = _signature
            self.signed += 1
        return transaction

class SiriCoinMiner(object):
    def __init__(self, NodeAddr, RewardsRecipient):
        self.node = NodeAddr
        self.signer = SignatureManager()
        self.difficulty = 1
        self.target = "0x" + "f"*64
        self.lastBlock = ""
        self.rewardsRecipient = w3.toChecksumAddress(RewardsRecipient)
        self.priv_key = w3.solidityKeccak(["string", "address"], ["SiriCoin Will go to M00N - Just a disposable key", self.rewardsRecipient])

        self.nonce = 0
        self.acct = w3.eth.account.from_key(self.priv_key)
        self.messages = b"null"
        
        self.timestamp = time.time()
        _txs = requests.get(f"{self.node}/accounts/accountInfo/{self.acct.address}").json().get("result").get("transactions")
        self.lastSentTx = _txs[len(_txs)-1]
        self.refresh()
    
    def refresh(self):
        info = requests.get(f"{self.node}/chain/miningInfo").json().get("result")
        self.target = info["target"]
        self.difficulty = info["difficulty"]
        self.lastBlock = info["lastBlockHash"]
        _txs = requests.get(f"{self.node}/accounts/accountInfo/{self.acct.address}").json().get("result").get("transactions")
        self.lastSentTx = _txs[len(_txs)-1]
        self.timestamp = time.time()
        self.nonce = 0
    
    def submitBlock(self, blockData):
        tx = self.signer.signTransaction(self.priv_key, {"data": json.dumps({"from": self.acct.address, "to": self.acct.address, "tokens": 0, "parent": self.lastSentTx, "blockData": blockData, "epoch": self.lastBlock, "type": 1})})
        self.refresh()
        try:
            txid = requests.get(f"{self.node}/send/rawtransaction/?tx={json.dumps(tx).encode().hex()}").json().get("result")[0]
            rgbPrint(f"Mined block {blockData['miningData']['proof']},\nsubmitted in transaction {txid}", "green")
            rgbPrint("Current Network Balance: " + str(requests.get(f"{self.node}/accounts/accountBalance/{self.rewardsRecipient}").json()["result"]["balance"]) + " Siro", "green") # code by luketherock868
            miner.startMining()
        except:
            pass
            
    def beaconRoot(self):
        messagesHash = sha3.keccak_256(self.messages).digest()
        bRoot = "0x" + sha3.keccak_256((b"".join([bytes.fromhex(self.lastBlock.replace("0x", "")), int(self.timestamp).to_bytes(32, 'big'), messagesHash, bytes.fromhex(self.rewardsRecipient.replace("0x", "")) ]))).hexdigest() # parent PoW hash (bytes32), beacon's timestamp (uint256), hash of messages (bytes32), beacon miner (address)
        return bRoot

    def formatHashrate(self, hashrate):
        if hashrate < 1000:
            # H's
            if len(str(round(hashrate, 2)).split('.', 1)[1]) == 1: return str(round(hashrate, 2)) + "0 H/s" 
            else: return str(round(hashrate, 2)) + " H/s"
        elif hashrate < 1000000:
            # KH's
            if len(str(round(hashrate/1000, 2)).split('.', 1)[1]) == 1: return str(round(hashrate/1000, 2)) + "0 KH/s" 
            else: return str(round(hashrate/1000, 2)) + " KH/s"
        elif hashrate < 1000000000:
            # MH's
            if len(str(round(hashrate/1000000, 2)).split('.', 1)[1]) == 1: return str(round(hashrate/1000000, 2)) + "0 MH/s" 
            else: return str(round(hashrate/1000000, 2)) + " MH/s"
        elif hashrate < 1000000000000:
            # GH's
            if len(str(round(hashrate/1000000000, 2)).split('.', 1)[1]) == 1: return str(round(hashrate/10000000, 2)) + "0 GH/s" 
            else: return str(round(hashrate/10000000, 2)) + " GH/s"
        
                
    def startMining(self):
        global RpcEnabled, first_run, bRoot
        if RpcEnabled:
            try:
                rpc = pypresence.Presence("998176088297570324")
                rpc.connect()
            except:
                RpcEnabled = False

        self.refresh()
        if first_run: rgbPrint(f"Started mining for {self.rewardsRecipient} on {the_node}", "yellow")
        hashes = []

        

        while True:
            self.refresh()
            bRoot = self.beaconRoot()
            bRoot_hasher = skein.skein256()
            bRoot_hasher.update(bytes.fromhex(bRoot.replace("0x", "")))

            first_run = False
            while (time.time() - self.timestamp) < hashrate_refreshRate:
                for i in range (hashes_per_list):
                    
                    finalHash = bRoot_hasher.copy()
                    finalHash.update(self.nonce.to_bytes(32, "big"))
                    hashes.append(groestlcoin_hash.getHash(b"".join([finalHash.digest(), self.nonce.to_bytes(32, "big")]), 64))
                    self.nonce +=1
                    

                for hash in hashes:
                    if int(int.from_bytes(hash, "big")) < int(self.target, 16):
                        validNonce = (self.nonce - (len(hashes) - hashes.index(hash)))
                        rawTX = ({"miningData" : {"miner": self.rewardsRecipient, "nonce": validNonce, "difficulty": self.difficulty, "miningTarget": self.target, "proof": "0x" + hash.hex()}, "parent": self.lastBlock, "messages": self.messages.hex(), "timestamp": int(self.timestamp), "son": "0"*64})           
                        self.submitBlock(rawTX)

                hashes.clear()
            
            rgbPrint("Last " + str(hashrate_refreshRate) + "s hashrate: " + self.formatHashrate((self.nonce / hashrate_refreshRate)), "yellow")
            if RpcEnabled:
                rpc.update(state="Mining siro on " + cpuinfo.get_cpu_info()['brand_raw'] + "!", details="Hashrate: " + self.formatHashrate((self.nonce / hashrate_refreshRate)) + ", Network balance: " + str(requests.get(f"{self.node}/accounts/accountBalance/{self.rewardsRecipient}").json()["result"]["balance"]) + " Siro", large_image="sirious", start=time.time())


if __name__ == "__main__":
    first_run = True
    address_valid = False
    
    
    # rgbPrint("-"*28 + " System " + "-"*28, "yellow")
    # rgbPrint("OS: " + platform.system() + " " + platform.release(), "yellow")
    # rgbPrint("CPU: " + cpuinfo.get_cpu_info()['brand_raw'] +" @ "+ cpuinfo.get_cpu_info()['hz_advertised_friendly'] + " (x"+str(cpuinfo.get_cpu_info()['count'])+")", "yellow")
    # rgbPrint("RAM: " + str(round(int(psutil.virtual_memory()[3]) / 1074000000, 2)) + " / " + str(round(float(psutil.virtual_memory()[0]) / 1074000000, 2)) + " GB", "yellow")
    # rgbPrint("-"*64, "yellow") # code by luketherock868
    
    Get_address()
        
    # try:
        # if requests.get(f"{MainNET}/chain/block/0", timeout=TimeOUT).json()["result"]["height"] == 0:
    the_node = "test-net"
    miner = SiriCoinMiner(MainNET, minerAddr)
    Continue_To_Junaid_net = False
    miner.startMining()
    # except requests.ConnectTimeout:
    #     Continue_To_Junaid_net = True

    # try:
    #     if Continue_To_Junaid_net and requests.get(f"{JunaidNET}/chain/block/1", timeout=TimeOUT).json()["result"]["height"] == 1:
    #         the_node = "Junaid-net"
    #         miner = SiriCoinMiner(JunaidNET, minerAddr)
    #         miner.startMining()
    # except requests.ConnectTimeout:
    #     rgbPrint("All networks are down, quitting the miner, goodbye!", "red")
    #     sys.exit()
        
