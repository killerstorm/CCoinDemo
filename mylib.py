import pycoin.tx
import urllib2
import json

class UTXO(object):
    def __init__(self, txhash, outindex, value, script):
        self.txhash = txhash
        self.outindex = outindex
        self.value = value
        self.script = script
    def get_pycoin_coin_source(self):
        le_txhash = self.txhash.decode('hex')[::-1]
        pycoin_txout = pycoin.tx.TxOut(self.value, self.script.decode('hex'))
        return (le_txhash, self.outindex, pycoin_txout)


class UTXOFetcher(object):
    def get_for_address(self, address):
        jsonData = urllib2.urlopen("http://blockchain.info/unspent?active=%s" % address).read()
        data = json.loads(jsonData)
        utxos = []
        for utxo_data in data['unspent_outputs']:
            txhash = utxo_data['tx_hash'].decode('hex')[::-1].encode('hex')
            utxo = UTXO(txhash, utxo_data['tx_output_n'], utxo_data['value'], utxo_data['script'])
            utxos.append(utxo)
        return utxos


class TransactionData(object):
    def __init__(self):
        self.unspent = UTXOFetcher()

