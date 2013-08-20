# CCoinDemo
# Last edited - Aug 20 2013 2:44 PST 
import hashlib
import ecdsa
import util
from Crypto.Cipher import AES
from json import loads, dumps
import urllib2

import binascii
import io

from pycoin import encoding
from pycoin.convention import tx_fee, btc_to_satoshi, satoshi_to_btc
from pycoin.services import blockchain_info
from pycoin.tx import Tx, UnsignedTx, TxOut, SecretExponentSolver

sha256 = lambda h: hashlib.sha256(h).digest()
ripemd160 = lambda h: hashlib.new("ripemd160", h).digest()
md5 = lambda h: hashlib.md5(h).digest()

class Colourer():
	def __init__(self):
		from ccoinagent import agent
		from ccoinagent import blockchain
		from ccoinagent import builder
		from ccoinagent import colordef
		from ccoinagent import store

		# Ripped from test.py

		self.blockchain_state = blockchain.BlockchainState("http://bitcoinrpc:6dE98wfc33UN8HacoWSHnyM3SP6qZv74ejX1p4RTufBo@localhost:8332/")
		self.store_conn = store.DataStoreConnection("color.db")

		self.cdstore = store.ColorDataStore(self.store_conn.conn)
		self.metastore = store.ColorMetaStore(self.store_conn.conn)

		genesis = {'txhash': 'a81a64bf90635b7a4313a96b850ced4ae579bef1ada11d485090f8bfbb7cf456',
				   'outindex': 0,
				   'height': 252730}

		self.colordef1 = colordef.OBColorDefinition(1, genesis)
		self.colordefman = agent.ColorDefinitionManager()

		self.cdbuilder = builder.FullScanColorDataBuilder(self.cdstore, self.blockchain_state, self.colordef1, self.metastore)
		
		self.mempoolcd = agent.MempoolColorData(self.blockchain_state)
		self.cdata = agent.ThickColorData(self.cdbuilder, self.mempoolcd, self.blockchain_state, self.colordefman, self.cdstore)

		self.ccagent = agent.ColoredCoinAgent(self.blockchain_state, self.cdata)
		self.ccagent.update()

class Address():
	def __init__(self, pubkey, privkey, rawPubkey, rawPrivkey):
		self.pubkey = pubkey
		self.privkey = privkey
		self.rawPrivkey = rawPrivkey
		self.rawPubkey = rawPubkey

	@classmethod
	def new(self):
		ecdsaPrivkey = ecdsa.SigningKey.generate(curve=ecdsa.curves.SECP256k1)
		ecdsaPubkey = ecdsaPrivkey.get_verifying_key()

		rawPrivkey = ecdsaPrivkey.to_string()
		rawPubkey = "\x00" + ripemd160(sha256("\x04" + ecdsaPubkey.to_string()))
		pubkeyChecksum = sha256(sha256(rawPubkey))[:4]
		rawPubkey += pubkeyChecksum

		pubkey = util.b58encode(rawPubkey)
		privkey = "\x80" + rawPrivkey
		privkeyChecksum = sha256(sha256(privkey))[:4]
		privkey = util.b58encode(privkey + privkeyChecksum)

		return self(pubkey, privkey, rawPubkey, rawPrivkey)

	@classmethod
	def fromObj(self, data):
		pubkey = data["pubkey"]
		privkey = data["privkey"]
		rawPubkey = data["rawPubkey"].decode("hex")
		rawPrivkey = data["rawPrivkey"].decode("hex")

		return self(pubkey, privkey, rawPubkey, rawPrivkey)

	def getJSONData(self):
		return {"pubkey":self.pubkey, "privkey":self.privkey, "rawPrivkey":self.rawPrivkey.encode("hex"), "rawPubkey":self.rawPubkey.encode("hex")}

	def getData(self):
		jsonData = urllib2.urlopen("http://blockchain.info/unspent?active=%s" % self.pubkey).read()
		data = loads(jsonData)
		return data

class Account():
	def __init__(self, addresses, username, passwordKey):
		self.addresses = addresses
		self.username = username
		self.passwordKey = passwordKey
		self.colourer = Colourer()

		self.allBalanceCache = None # This includes coloured coins. Used to check whether we should perform getany
		self.balanceCaches = {} # "balance":normal balance, colour_id:[balance, label]

	@classmethod
	def new(self):
		print "Enter username"
		username = raw_input("> ")

		print "Enter password"
		passwordKey = util.KDF(raw_input("> "))

		addresses = [Address.new()]
		
		return self(addresses, username, passwordKey)

	@classmethod
	def login(self):
		print "Enter username"
		username = raw_input("> ")

		print "Enter password"
		passwordKey = util.KDF(raw_input("> "))

		fname = md5(username).encode("hex") + ".walletdat"
		f = open(fname, "r")
		cipherData = f.read()
		f.close()

		cipher = AES.new(passwordKey)
		jsonData = util.removeNearest16Pad(cipher.decrypt(cipherData))

		data = loads(jsonData)

		addresses = []

		for i in data["addresses"]:
			addresses.append(Address.fromObj(i))

		return self(addresses, username, passwordKey)

	def save(self):
		data = {}
		data["addresses"] = [i.getJSONData() for i in self.addresses]
		jsondata = dumps(data)

		cipher = AES.new(self.passwordKey)
		padData = util.padToNearest16(jsondata)
		cipherData = cipher.encrypt(padData)
		fname = md5(self.username).encode("hex") + ".walletdat"
		f = open(fname, "w")
		f.write(cipherData)
		f.close()

	def printAddresses(self):
		for i in self.addresses:
			print i.pubkey

	def printKeys(self):
		for i in self.addresses:
			print "Public Key: %s Private Key: %s" % (i.pubkey, i.privkey)

	def newAddress(self):
		self.addresses.append(Address.new())
		print "Public Key: %s Private Key: %s" % (self.addresses[-1].pubkey, self.addresses[-1].privkey)

	def getBalance(self):
		addressData = []
		for i in self.addresses:
			addressData.append(i.getData())

		allBalance = 0
		for address in addressData:
			for utxo in address["unspent_outputs"]:
				allBalance += int(utxo["value"])

		if allBalance != self.allBalanceCache: # Check for coloured-ness of all coins cuz new coins are here!
			self.colourer.ccagent.update()

			balances = {0:[0, "balance"]}

			for addr in addressData:
				for utxo in addr["unspent_outputs"]:
					utxohash = utxo["tx_hash"].decode("hex")[::-1].encode("hex")
					utxodata = self.colourer.ccagent.color_data.get_any(utxohash, utxo["tx_output_n"])
					if utxodata == []:
						balances[0][0] += utxo["value"]
					elif len(utxodata) == 1:
						colour_id = utxodata[0][0]
						value = utxodata[0][1]
						label = utxodata[0][2]
						if not colour_id in balances:
							balances[colour_id] = [value, label]
						else:
							balances[colour_id][0] += value

			#self.setColourChecked(checked)
			self.balanceCaches = balances

			maxLabelSize = len(balances[max(balances, key=lambda i: len(balances[i][1]))][1])

			for i in balances.keys():
				print "(%i) %s: %d" % (i, balances[i][1].ljust(maxLabelSize, " "), balances[i][0])

	#def getColourChecked(self):
	#	try:
	#		f = open("ColourChecked.dat", "r")
	#		data = f.readlines()
	#		return data
	#	except:
	#		return []
	#
	#def setColourChecked(self, txhashes):
	#	f = open("ColourChecked.dat", "a")
	#	for i in txhashes:
	#		f.write(i + "\n")
	#	f.close()

	def send(self, ddestination_address, dcolourid = None):
		destination_address = [ddestination_address]
		source_address = [self.addresses[i].pubkey for i in range(len(self.addresses))]
		wifs = [self.addresses[i].privkey for i in range(len(self.addresses))]


		self.colourer.ccagent.update()

		total_value = 0
		coins_from = []

		for bca in source_address:
			coins_sources = blockchain_info.coin_sources_for_address(bca)

			for source in coins_sources:
				txhashhex = source[0][::-1].encode("hex")
				txn = source[1]
				utxodata = self.colourer.ccagent.color_data.get_any(txhashhex, txn)
				if not utxodata: utxodata = [[None]]

				if not utxodata[0][0] == dcolourid:
					coins_sources.remove(source)

			coins_from.extend(coins_sources)
			total_value += sum(cs[-1].coin_value for cs in coins_sources)

		secret_exponents = []
		for l in wifs:
			secret_exponents.append(encoding.wif_to_secret_exponent(l))

		coins_to = []
		total_spent = 0
		for daa in destination_address:
			address, amount = daa[0], daa[1]
			amount = btc_to_satoshi(amount)
			total_spent += amount
			coins_to.append((amount, address))

		change = (total_value - total_spent) - 10000

		if change >= 1:
			coins_to.append((change, source_address[0]))

		unsigned_tx = UnsignedTx.standard_tx(coins_from, coins_to)
		solver = SecretExponentSolver(secret_exponents)
		new_tx = unsigned_tx.sign(solver)
		s = io.BytesIO()
		new_tx.stream(s)
		tx_bytes = s.getvalue()
		tx_hex = binascii.hexlify(tx_bytes).decode("utf8")
		recommended_tx_fee = tx_fee.recommended_fee_for_tx(new_tx)

		print tx_hex

		URL = "http://blockchain.info/pushtx"
		urllib2.urlopen(URL, data=tx_hex)

class Wallet():
	def __init__(self):
		self.isRunning = True
		self.title()
		self.prompt()

	def title(self):
		print "Register"
		print "Login"
		m = raw_input("> ").lower()

		if m in "register reg new r".split(" "):
			self.account = Account.new()
		elif m in "login log l".split(" "):
			self.account = Account.login()
		else:
			print "Unknown command: %s" % m
			self.title()

	def prompt(self):
		while self.isRunning:
			print "Show addresses"
			print "Show keys"
			print "New address"
			print "Show Balance"
			print "Send"
			print "Save"
			print "Quit"
			m = raw_input("> ").lower()

			if m in "addresses.show addresses.show address.show addr.addr.address.pub.pubkey.pub key.pub keys".split("."):
				self.account.printAddresses()
			elif m in "keys.show keys.private keys.private key.private.priv.privkey.priv key.priv keys.privkeys".split("."):
				self.account.printKeys()
			elif m in "new.new address.n.new addr.n addr".split("."):
				self.account.newAddress()
			elif m in "balance.bal.show bal.show balance".split("."):
				self.account.getBalance()
			elif m == "send":
				daa = raw_input("Destination Address > ")
				amount = float(raw_input("Amount > "))
				colour = int(raw_input("Colour ID > "))
				self.account.send([daa, amount], colour)
			elif m == "save":
				self.account.save()
			elif m in "quit q close".split(" "):
				self.account.save()
				self.isRunning = False
			else:
				print "Unknown Command: %s" % m

	def update(self):
		pass

if __name__ == "__main__":
	w = Wallet()