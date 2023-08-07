from heu import phe

kit = phe.setup(phe.SchemaType.DJ, 2048)
c1 = kit.encryptor().encrypt_raw(3)
c2 = kit.evaluator().add(c1, c1)
print(kit.decryptor().decrypt_raw(c2)) #6