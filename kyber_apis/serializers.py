from rest_framework import serializers
from kyber_py_main.kyber import Kyber512
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
from os import urandom


class GenerateKeysSerializer(serializers.Serializer):
    def get(self):
        pk, sk = Kyber512.keygen()
        pk_base64 = base64.b64encode(pk).decode('utf-8')
        sk_base64 = base64.b64encode(sk).decode('utf-8')
        return {
                    "pk": pk_base64,
                    "sk": sk_base64
                }
    
class EncryptDataSerializer(serializers.Serializer):
    text = serializers.CharField(required=True, write_only=True, min_length=1)
    pk = serializers.CharField(required=True, write_only=True)
    sk = serializers.CharField(required=True, write_only=True)
    associated_data = serializers.CharField(required=False)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        additional_fields = instance
        data.update(additional_fields)
        return data
    
    def validate(self, data):
        return data

    def create(self, validated_data):
        text = validated_data['text']
        pk = validated_data['pk']
        sk = validated_data['sk']
        associated_data = validated_data.get('associated_data', None)

        data_bytes = text.encode('utf-8')
        salt = pk.encode('utf-8') if isinstance(pk, str) else pk

        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key_material = sk.encode('utf-8')  
        key = kdf.derive(key_material)
        aesgcm = AESGCM(key)
        nonce = urandom(12)
        
        if isinstance(associated_data, str):  
            associated_data = associated_data.encode('utf-8')

        ciphertext = aesgcm.encrypt(nonce, data_bytes, associated_data)

        encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
        encoded_nonce = base64.b64encode(nonce).decode('utf-8')

        data = {
                    "cipher_text": encoded_ciphertext,
                    "nonce": encoded_nonce,
                    "associated_data": associated_data
                }

        return {
                    "cipher_text": encoded_ciphertext,
                    "nonce": encoded_nonce,
                    "associated_data": associated_data
                }
    
class DecryptDataSerializer(serializers.Serializer):
    encrypted_text = serializers.CharField(required=True, write_only=True, min_length=1)
    pk = serializers.CharField(required=True, write_only=True)
    sk = serializers.CharField(required=True, write_only=True)
    nonce = serializers.CharField(required=True, write_only=True)
    associated_data = serializers.CharField(required=False)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        additional_fields = instance
        data.update(additional_fields)
        return data
    
    def validate(self, data):
        return data
    
    def create(self, validated_data):
        encrypted_text = validated_data['encrypted_text']
        pk = validated_data['pk']
        sk = validated_data['sk']
        nonce = validated_data['nonce']
        associated_data = validated_data.get('associated_data', None)

        key_material = sk.encode('utf-8')  
        salt = pk.encode('utf-8') if isinstance(pk, str) else pk  

        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        key = kdf.derive(key_material)
        aesgcm = AESGCM(key) 

        if isinstance(associated_data, str):  
            associated_data = associated_data.encode('utf-8')

        encrypted_bytes = base64.b64decode(encrypted_text)

        nonce_new = base64.b64decode(nonce)
        decrypted_data = aesgcm.decrypt(nonce_new, encrypted_bytes, associated_data)
        decrypted_string = decrypted_data.decode('utf-8')

        return {"decrypted_string": decrypted_string}
    


    
