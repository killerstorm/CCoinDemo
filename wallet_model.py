class ColorSet(object):
    pass


class AssetDefinition(object):
    def __init__(self, config):
        self.moniker = config.get('moniker')
    def get_moniker(self):
        return self.moniker
    def get_color_set(self):
        return ColorSet()
    def get_utxo_value(self):
        pass

class AssetDefinitionManager(object):
    """manages asset definitions"""
    def __init__(self, config):
        self.asset_definitions = []
        self.assdef_by_moniker = {}
        for ad_config in config.get('asset_definitions'):
            assdef = AssetDefinition(ad_config)
            asset_definitions.append(assdef)
            moniker = assdef.get_moniker()
            if moniker:
                if moniker in assdef_by_moniker:
                    raise Exception('more than one asset definition have same moniker')
                self.assdef_by_moniker[moniker] = assdef
    def get_asset_by_moniker(self, moniker):
        return self.assdef_by_moniker.get(moniker)

class CoinQuery(object):
    """can be used to request UTXOs satisfying certain criteria"""
    def __init__(self, model, asset):
        self.model = model
        self.asset = asset
    def get_result(self):
        addr_man = self.model.get_address_manager()
        color_set = self.asset.get_color_set()
        addresses = addr_man.get_addresses_for_color_set(color_set)
        utxos = []
        for address in addresses:
            utxos.extend(address.getUTXOs(color_set))
        return utxos

class Address(object):
    pass

class WalletAddressManager(object):
    def __init__(self, config):
        self.addreses = []
        for addr_conf in config.get('addresses'):
            address = Address(addr_conf)
            self.addresses.append(address)
        
    def get_addresses_for_color_set(self, color_set):
        return [addr for addr in self.addresses if color_set.contains(address.colorid)]

class WalletController(object):
    def __init__(self, model):
        self.model = model

    def get_balance(self, asset):
        cq = CoinQuery(self.model, asset)
        utxo_list = cq.get_result()
        value_list = [asset.get_utxo_value(utxo) for utxo in utxo_list]
        return sum(value_list)

class WalletModel(object):
    def __init__(self, config):
        self.ass_def_man = AssetDefinitionManager(config)
        self.address_man = WalletAddressManager(config)
    def get_asset_definition_manager(self):
        return self.ass_def_man
    def get_address_manager(self):
        return self.address_man

class WalletInterface(object):
    pass

