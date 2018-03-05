import base64
import boto3
import os
from Crypto.Cipher import AES


def fetch_decryption_key():
    encrypted_key = __fetch_encrypted_key()
    return __decrypt_key(encrypted_key)


def decrypt_message(encrypted_message, decryption_key):
    cipher = AES.new(decryption_key, AES.MODE_ECB)
    message = base64.b64decode(encrypted_message)
    return __unpad(cipher.decrypt(message)).decode('utf-8')


def __unpad(message):
    """
    Expects a string padded at the end of the string, where the final character is the number of padded characters.
    eg
    foobar666666 => foobar, as the final character is 6, indicating 6 characters should be removed.
    """
    final_character = message[-1]
    return message[0:-int(final_character)]


def __fetch_encrypted_key():
    s3_client = boto3.client('s3')
    bucket_name = os.environ['DECRYPTION_KEY_BUCKET_NAME']
    filename = os.environ['DECRYPTION_KEY_FILE_NAME']
    response = s3_client.get_object(Bucket=bucket_name, Key=filename)
    return response['Body'].read()


def __decrypt_key(encrypted_key):
    kms_client = boto3.client('kms')
    return kms_client.decrypt(CiphertextBlob=encrypted_key)['Plaintext'].decode('utf-8')

